from zipfile import ZipFile
from io import BytesIO

import ipfix
import panfix
import pandas as pd
import numpy as np

S = panfix.TCP_SYN
SAE = (panfix.TCP_SYN | panfix.TCP_ECE | panfix.TCP_ACK)
SEW = (panfix.TCP_SYN | panfix.TCP_ECE | panfix.TCP_CWR)
SAEW = (panfix.TCP_SYN | panfix.TCP_ECE | panfix.TCP_ACK | panfix.TCP_CWR)
QECT0 = panfix.QOF_ECT0
QECT1 = panfix.QOF_ECT1
QCE = panfix.QOF_CE

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()
ipfix.ie.use_specfile("qof.iespec")

def index_intersect(dfs):
    """Return the intersection of the indices of passed-in dataframes"""
    idx = dfs[0].index
    for i in range(1, len(dfs)):
        idx = idx & dfs[i].index
    return pd.Index(idx.unique(), name=dfs[0].index.name)


def load_es_df(filepath_or_buffer, vp, trial):
    # raw dataframe
    df = pd.read_csv(filepath_or_buffer, names=["time", "rank", "site", "ip",
                                      "ecn0rv","ecn0sp","ecn1rv","ecn1sp",
                                      "ecn0http","ecn1http"],
                     usecols=[0,1,2,3,4,5,6,7,16,19])

    # cast IP address to string
    df['ip'] = df['ip'].astype(np.str)

    # drop all rows with garbage addresses
    df = df[df['ip'].apply(lambda x: not x.startswith("[::"))]
    df = df[df['ip'].apply(lambda x: not x.startswith("[fe80:"))]
    df = df[df['ip'].apply(lambda x: not x.startswith("[fc00:"))]
    df = df[df['ip'].apply(lambda x: not x.startswith("[64:ff9b:"))]
    df = df[df['ip'].apply(lambda x: not x.startswith("0."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("10."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("127."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("169.254."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.16."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.17."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.18."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.19."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.20."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.21."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.22."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.23."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.24."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.25."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.26."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.27."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.28."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.29."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.30."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("172.31."))]
    df = df[df['ip'].apply(lambda x: not x.startswith("192.168."))]

    # tag IPv6 addresses
    df["ip6"] = df['ip'].apply(lambda x: x.startswith("["))

    # cast timestamp to datetime
    df['time'] = pd.to_datetime(df['time'] * 1e9)

    # rank is an integer
    df['rank'] = df['rank'].astype(np.uint32)

    # sitr is a string
    df['site'] = df['site'].astype(np.str)

    # cast ports
    df["ecn0sp"] = df["ecn0sp"].astype(np.uint16)
    df["ecn1sp"] = df["ecn1sp"].astype(np.uint16)

    # categorize errors
    df["ecn0rv"] = pd.Categorical(df['ecn0rv'].fillna("Success"))
    df["ecn1rv"] = pd.Categorical(df['ecn1rv'].fillna("Success"))
    df["ecn0ok"] = (df['ecn0rv'] == "Success")
    df["ecn1ok"] = (df['ecn1rv'] == "Success")

    # cast HTTP status
    df["ecn0http"] = df["ecn0http"].fillna(0).astype(np.uint16)
    df["ecn1http"] = df["ecn1http"].fillna(0).astype(np.uint16)

    # annotate mismatch between error states
    # (the error codes are less interesting; the fact that the status is different moreso)
    df["ecndep"] = (df["ecn0ok"] != df["ecn1ok"])

    # annotate with vp and trial, in case we want pivot/select on these later
    df["vp"] = vp
    df["trial"] = trial

    # and now build the index
    df.index = pd.Index(df['ip'], name="ip")
    del(df['ip'])

    return df


def load_qof_df(filename, ipv6_mode=False, open_fn=open, count=None):
    # select destination address IE
    if ipv6_mode:
        dip_ie = "destinationIPv6Address"
        sip_ie = "sourceIPv6Address"
    else:
        dip_ie = "destinationIPv4Address"
        sip_ie = "sourceIPv4Address"

    ienames = (
        "flowStartMilliseconds",
        "flowEndMilliseconds",
        "octetDeltaCount",
        "reverseOctetDeltaCount",
        dip_ie,
        sip_ie,
        "sourceTransportPort",
        "destinationTransportPort",
        "initialTCPFlags",
        "reverseInitialTCPFlags",
        "reverseQofTcpCharacteristics",
        "packetDeltaCount",
        "reversePacketDeltaCount",
        "lastSynTcpFlags",
        "reverseLastSynTcpFlags"
    )

    # raw dataframe
    df = panfix.dataframe_from_ipfix(filename, open_fn=open_fn, count=count, ienames=ienames)

    # turn timestamps into pandas-friendly types
    df = panfix.coerce_timestamps(df)

    # cast flags down to reduce memory consumption
    df["initialTCPFlags"] = df["initialTCPFlags"].astype(np.uint8)
    df["reverseInitialTCPFlags"] = df["reverseInitialTCPFlags"].astype(np.uint8)

    # drop all flows without dport == 80
    df = df[df["destinationTransportPort"] == 80]

    # drop all flows without an initial SYN
    df = df[np.bitwise_and(df["initialTCPFlags"], S) > 0]

    # cast addresses to strings
    # for the index, ipv6 addresses are enclosed by [] to match ecnspider data index
    if ipv6_mode:
        df.index = df[dip_ie].apply(lambda x: "["+str(x)+"]")
    else:
        df.index = df[dip_ie].apply(str)

    df[dip_ie] = df[dip_ie].apply(str)
    df[sip_ie] = df[sip_ie].apply(str)

    # mark IPv6 mode
    df['ip6'] = ipv6_mode

    # mark ecn attempted
    df["ecnAttempted"] = np.bitwise_and(df["lastSynTcpFlags"],SAEW) == SEW

    # rename columns
    df['sip'] = df[sip_ie]
    df['dip'] = df[dip_ie]
    del(df[dip_ie])
    del(df[sip_ie])

    return df


def split_qof_df(df):
    # split on attempt
    qe0_df = df[~df['ecnAttempted']]
    qe1_df = df[ df['ecnAttempted']]

    # take only the biggest object HACK HACK HACK
    qe0_df = qe0_df.sort_values(by="reverseOctetDeltaCount",ascending=False).groupby(level=0).first()
    qe1_df = qe1_df.sort_values(by="reverseOctetDeltaCount",ascending=False).groupby(level=0).first()

    # take only rows appearing in both
    qof_idx = index_intersect([qe0_df, qe1_df])
    qe0_df = qe0_df.loc[qof_idx]
    qe1_df = qe1_df.loc[qof_idx]

    return (qe0_df, qe1_df)

def map_new_format_sub(row, suffix, ecnXok):
    return {
        'first'        : row['flowStartMilliseconds'+suffix],
        'last'         : row['flowEndMilliseconds'+suffix],
        'sp'           : row['sourceTransportPort'+suffix],
        'dp'           : row['destinationTransportPort'+suffix],
        'connstate'    : row[ecnXok],
        'ecnstate'     : row['ecnAttempted'+suffix],
        'fwd_syn_flags': row['initialTCPFlags'+suffix],
        'rev_syn_flags': row['reverseInitialTCPFlags'+suffix],
        'pkt_fwd'      : row['packetDeltaCount'+suffix],
        'pkt_rev'      : row['reversePacketDeltaCount'+suffix],
        'oct_fwd'      : row['octetDeltaCount'+suffix],
        'oct_rev'      : row['reverseOctetDeltaCount'+suffix],
        'ecn_zero'     : row['reverseQofTcpCharacteristics'+suffix] & QECT0,
        'ecn_one'      : row['reverseQofTcpCharacteristics'+suffix] & QECT1,
        'ce'           : row['reverseQofTcpCharacteristics'+suffix] & QCE
    }

def map_new_format(row):
    return {
        'site': row['site'],
        'dip': row['dip_0'],
        'proto': 6,
        'ecn0': map_new_format_sub(row, '_0', 'ecn0ok'),
        'ecn1': map_new_format_sub(row, '_1', 'ecn1ok')
    }

def prepare_data(filename, metadata, data):
    zf = ZipFile(BytesIO(data))

    def get_filename_from_zip(endswith):
        for zinfo in zf.filelist:
            if zinfo.filename.endswith(endswith):
                return zinfo.filename

        raise ValueError("No file ending with '{}' in zip file.".format(endswith))

    ipfix_filename = get_filename_from_zip('.ipfix')
    csv_filename = get_filename_from_zip('.csv')

    es_df = load_es_df(zf.open(csv_filename), "ams", 0)

    q4_df = load_qof_df(ipfix_filename, open_fn=zf.open, ipv6_mode=False)
    q6_df = load_qof_df(ipfix_filename, open_fn=zf.open, ipv6_mode=True)

    q4_e0_df, q4_e1_df = split_qof_df(q4_df)
    q6_e0_df, q6_e1_df = split_qof_df(q6_df)

    q4_merged = pd.merge(q4_e0_df, q4_e1_df, left_index=True, right_index=True, suffixes=('_0', '_1'))
    q6_merged = pd.merge(q6_e0_df, q6_e1_df, left_index=True, right_index=True, suffixes=('_0', '_1'))

    q_merged = q4_merged.append(q6_merged)

    merged = pd.merge(es_df, q_merged, left_index=True, right_index=True)

    return merged
