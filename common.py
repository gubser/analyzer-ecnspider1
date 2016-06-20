import pandas as pd


def index_intersect(dfs):
    """Return the intersection of the indices of passed-in dataframes"""
    idx = dfs[0].index
    for i in range(1, len(dfs)):
        idx = idx & dfs[i].index
    return pd.Index(idx.unique(), name=dfs[0].index.name)