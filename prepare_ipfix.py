import numpy as np
import pandas as pd
import ipfix
import panfix

from common import index_intersect

# configure IPFIX information model
ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()
ipfix.ie.use_specfile("qof.iespec")

# Define flags
S = panfix.TCP_SYN
R = panfix.TCP_RST
SA = panfix.TCP_SYN | panfix.TCP_ACK
SEW = (panfix.TCP_SYN | panfix.TCP_ECE | panfix.TCP_CWR)
SAE = (panfix.TCP_SYN | panfix.TCP_ECE | panfix.TCP_ACK)
SAEW = (panfix.TCP_SYN | panfix.TCP_ECE | panfix.TCP_ACK | panfix.TCP_CWR)
QECT = (panfix.QOF_ECT0 | panfix.QOF_ECT1)
QECT0 = panfix.QOF_ECT0
QECT1 = panfix.QOF_ECT1
QCE = panfix.QOF_CE

# iain's last syn qof characteristics flags
QSYNECT0 = 0x0100
QSYNECT1 = 0x0200
QSYNCE   = 0x0400

def load_qof_df(filename, ipv6_mode=False, open_fn=open, spider_idx=None, count=None):
    # select destination address IE
    if ipv6_mode:
        dip_ie = "destinationIPv6Address"
    else:
        dip_ie = "destinationIPv4Address"

    # raw dataframe
    df = panfix.dataframe_from_ipfix(filename, open_fn=open_fn, count=count,
               ienames=(  "flowStartMilliseconds",
                          "flowEndMilliseconds",
                          "octetDeltaCount",
                          "reverseOctetDeltaCount",
                          "transportOctetDeltaCount",
                          "reverseTransportOctetDeltaCount",
                          "tcpSequenceCount",
                          "reverseTcpSequenceCount",
                          dip_ie,
                          "sourceTransportPort",
                          "destinationTransportPort",
                          "initialTCPFlags",
                          "reverseInitialTCPFlags",
                          "unionTCPFlags",
                          "reverseUnionTCPFlags",
                          "lastSynTcpFlags",
                          "reverseLastSynTcpFlags",
                          "tcpSynTotalCount",
                          "reverseTcpSynTotalCount",
                          "qofTcpCharacteristics",
                          "reverseQofTcpCharacteristics",
                          "packetDeltaCount",
                          "reversePacketDeltaCount",
                          "reverseMinimumTTL",
                          "reverseMaximumTTL"))

    # turn timestamps into pandas-friendly types
    df = panfix.coerce_timestamps(df)

    # cast flags down to reduce memory consumption
    df["initialTCPFlags"] = df["initialTCPFlags"].astype(np.uint8)
    df["reverseInitialTCPFlags"] = df["reverseInitialTCPFlags"].astype(np.uint8)
    df["unionTCPFlags"] = df["unionTCPFlags"].astype(np.uint8)
    df["reverseUnionTCPFlags"] = df["reverseUnionTCPFlags"].astype(np.uint8)
    df["lastSynTcpFlags"] = df["lastSynTcpFlags"].astype(np.uint8)
    df["reverseLastSynTcpFlags"] = df["reverseLastSynTcpFlags"].astype(np.uint8)

    # drop all flows without dport == 80
    df = df[df["destinationTransportPort"] == 80]
    del(df["destinationTransportPort"])

    # drop all flows without an initial SYN
    df = df[np.bitwise_and(df["initialTCPFlags"], S) > 0]

    # cast addresses to strings to match ecnspider data
    if ipv6_mode:
        df[dip_ie] = df[dip_ie].apply(lambda x: "["+str(x)+"]")
    else:
        df[dip_ie] = df[dip_ie].apply(str)

    # mark IPv6 mode
    df['ip6'] = ipv6_mode

    # now build the index
    df.index = pd.Index(df[dip_ie], name="ip")
    del(df[dip_ie])

    # filter on index if requested
    if spider_idx is not None:
        qof_idx = pd.Index((spider_idx & df.index).unique(), name=spider_idx.name)
        df = df.loc[qof_idx]

    # Now annotate the dataframe with ECN and establishment columns
    df["ecnAttempted"] = np.bitwise_and(df["lastSynTcpFlags"],SAEW) == SEW
    df["ecnNegotiated"] = np.bitwise_and(df["reverseLastSynTcpFlags"],SAEW) == SAE
    df["ecnCapable"] = np.bitwise_and(df["reverseQofTcpCharacteristics"],QECT0) > 0
    df["ecnECT1"] = np.bitwise_and(df["reverseQofTcpCharacteristics"],QECT1) > 0
    df["ecnCE"] = np.bitwise_and(df["reverseQofTcpCharacteristics"],QCE) > 0
    df["didEstablish"] = ((np.bitwise_and(df["lastSynTcpFlags"], S) == S) &
                          (np.bitwise_and(df["reverseLastSynTcpFlags"], SA) == SA))
    df["isUniflow"] = (df["reverseMaximumTTL"] == 0)

    return df

def split_qof_df(df):
    # split on attempt
    qe0_df = df[~df['ecnAttempted']]
    qe1_df = df[ df['ecnAttempted']]

    # take only the biggest object HACK HACK HACK
    qe0_df = qe0_df.sort("reverseTransportOctetDeltaCount",ascending=False).groupby(level=0).first()
    qe1_df = qe1_df.sort("reverseTransportOctetDeltaCount",ascending=False).groupby(level=0).first()

    # take only rows appearing in both
    qof_idx = index_intersect([qe0_df, qe1_df])
    qe0_df = qe0_df.loc[qof_idx]
    qe1_df = qe1_df.loc[qof_idx]

    return (qe0_df, qe1_df)

def flowmatrix_columns(mq_df):
    return filter(lambda x: x != "ip6", mq_df.columns)

def flowmatrix(qof_dfs, labels):
    mq_dfs = []
    for qof_df in qof_dfs:
        # split on ecn attempted
        (qe0_df, qe1_df) = split_qof_df(qof_df)

        # and merge back together
        mqof_df = qe0_df.loc[:,["ip6", "didEstablish", "ecnCapable", "ecnECT1", "ecnCE",
                                "lastSynTcpFlags", "reverseLastSynTcpFlags",
                                "reverseUnionTCPFlags", "reverseMaximumTTL"]]
        mqof_df.columns = ["ip6", "e0", "e0ect0", "e0ect1", "e0ce",
                           "e0f", "e0rf", "e0ruf", "ttl"]
        mqof_df["z0"] = (qe0_df["reverseTransportOctetDeltaCount"] == 0)
        mqof_df["z1"] = (qe1_df["reverseTransportOctetDeltaCount"] == 0)
        mqof_df["e1"] = qe1_df["didEstablish"]
        mqof_df["neg"] = qe1_df["ecnNegotiated"]
        # markings on ECN negotiated flows
        mqof_df["ect0"] = qe1_df["ecnCapable"]
        mqof_df["ect1"] = qe1_df["ecnECT1"]
        mqof_df["ce"] = qe1_df["ecnCE"]
        mqof_df["synect0"] = np.bitwise_and(qe1_df["reverseQofTcpCharacteristics"], QSYNECT0) == QSYNECT0
        mqof_df["synect1"] = np.bitwise_and(qe1_df["reverseQofTcpCharacteristics"], QSYNECT1) == QSYNECT1
        mqof_df["synce"] = np.bitwise_and(qe1_df["reverseQofTcpCharacteristics"], QSYNCE) == QSYNCE
        # markings on non-negotiated flows
        mqof_df["e0ect0"] =    qe0_df["ecnCapable"]
        mqof_df["e0ect1"] =    qe0_df["ecnECT1"]
        mqof_df["e0ce"] =      qe0_df["ecnCE"]
        mqof_df["e0synect0"] = np.bitwise_and(qe0_df["reverseQofTcpCharacteristics"], QSYNECT0) == QSYNECT0
        mqof_df["e0synect1"] = np.bitwise_and(qe0_df["reverseQofTcpCharacteristics"], QSYNECT1) == QSYNECT1
        mqof_df["e0synce"] =   np.bitwise_and(qe0_df["reverseQofTcpCharacteristics"], QSYNCE) == QSYNCE

        mqof_df["refl"] = np.bitwise_and(qe1_df["reverseLastSynTcpFlags"], SAEW) == SAEW

        # add to list of merged dataframes
        mq_dfs.append(mqof_df)

    # use only items in every dataframe
    idx = index_intersect(mq_dfs)

    # make an initial dataframe from the first
    pfx = labels[0]+"-"
    cat_df = mq_dfs[0].loc[idx]
    cat_df.columns = ["ip6"] + [pfx + col for col in flowmatrix_columns(mq_dfs[0])]
    cat_df[pfx+"ect"] = cat_df[pfx+"ect0"] | cat_df[pfx+"ect1"]
    cat_df[pfx+"negok"] = cat_df[pfx+"neg"] & cat_df[pfx+"ect"]

    # now add columns to the catdf
    for i in range(1, len(mq_dfs)):
        pfx = labels[i]+"-"
        for col in flowmatrix_columns(mq_dfs[i]):
            cat_df[pfx+col] = mq_dfs[i].loc[idx][col]
        cat_df[pfx+"ect"] = cat_df[pfx+"ect0"] | cat_df[pfx+"ect1"]
        cat_df[pfx+"negok"] = cat_df[pfx+"neg"] & cat_df[pfx+"ect"]


    # now some sums
    sum_cols = ["negok","neg","ect","refl",
                "ect0","ect1","ce",
                "synect0","synect1","synce",
                "e0ect0","e0ect1","e0ce",
                "e0synect0","e0synect1","e0synce",
                "e1","e0","z1","z0"]
    for sum_col in sum_cols:
        cat_df[sum_col+"-sum"] = cat_df.loc[:,[label+"-"+sum_col for label in labels]].sum(axis=1)

    return cat_df