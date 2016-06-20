import pandas as pd
import numpy as np

from common import index_intersect

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

def connmatrix(es_dfs, vps, trials):
    # use only items in every dataframe
    idx = index_intersect(es_dfs)

    # make an initial dataframe from the first
    e0col = "-".join([str(vps[0]),str(trials[0]),"e0"])
    e0cols = [e0col]
    e1col = "-".join([str(vps[0]),str(trials[0]),"e1"])
    e1cols = [e1col]
#     eqcol = "-".join([str(vps[0]),str(trials[0]),"eq"])
#     eqcols = [eqcol]
#     depcol = "-".join([str(vps[0]),str(trials[0]),"dep"])
#     depcols = [depcol]
#     oddcol = "-".join([str(vps[0]),str(trials[0]),"odd"])
#     oddcols = [oddcol]
    cat_df = es_dfs[0].loc[idx, ["rank", "site", "ip6", "ecn0ok", "ecn1ok"]]
    cat_df.columns = ["rank", "site", "ip6", e0col, e1col]
#     cat_df[eqcol] = (cat_df[e0col] & cat_df[e1col]) | (~cat_df[e0col] & ~cat_df[e1col])
#     cat_df[depcol] = cat_df[e0col] & ~cat_df[e1col]
#     cat_df[oddcol] = ~cat_df[e0col] & cat_df[e1col]

    # now add columns to the catdf
    for i in range(1, len(es_dfs)):
        e0col = "-".join([str(vps[i]),str(trials[i]),"e0"])
        e0cols += [e0col]
        e1col = "-".join([str(vps[i]),str(trials[i]),"e1"])
        e1cols += [e1col]
#         eqcol = "-".join([str(vps[i]),str(trials[i]),"eq"])
#         eqcols += [eqcol]
#         depcol = "-".join([str(vps[i]),str(trials[i]),"dep"])
#         depcols += [depcol]
#         oddcol = "-".join([str(vps[i]),str(trials[i]),"odd"])
#         oddcols += [oddcol]
        cat_df[e0col] = es_dfs[i].loc[idx]["ecn0ok"]
        cat_df[e1col] = es_dfs[i].loc[idx]["ecn1ok"]
#         cat_df[eqcol] = (cat_df[e0col] & cat_df[e1col]) | (~cat_df[e0col] & ~cat_df[e1col])
#         cat_df[depcol] = cat_df[e0col] & ~cat_df[e1col]
#         cat_df[oddcol] = ~cat_df[e0col] & cat_df[e1col]

#     # add a few columns summarizing all
#     # all eq = no evidence of ECN dependency
#     cat_df["all-eq"] = cat_df.loc[:,eqcols].all(axis=1)
#     # count of equal trials
#     cat_df["eq-sum"] = cat_df.loc[:,eqcols].sum(axis=1)
#     # count of e0 connections
#     cat_df["e0-sum"] = cat_df.loc[:,e0cols].sum(axis=1)
#     # count of e1 connections
#     cat_df["e1-sum"] = cat_df.loc[:,e1cols].sum(axis=1)
#     # count of odd connections
#     cat_df["dep-sum"] = cat_df.loc[:,depcols].sum(axis=1)
#     # count of odd connections
#     cat_df["odd-sum"] = cat_df.loc[:,oddcols].sum(axis=1)
#     # all conn = no connection failure at all
#     cat_df["all-conn"] = cat_df.loc[:,e0cols+e1cols].all(axis=1)
#     # no conn = permanent connection failure
#     cat_df["no-conn"] = ~cat_df.loc[:,e0cols+e1cols].any(axis=1)

    return cat_df
