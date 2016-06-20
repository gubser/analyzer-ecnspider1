import itertools
from zipfile import ZipFile
from io import BytesIO

import pandas as pd
import numpy as np

from prepare_csv import load_es_df, connmatrix
from prepare_ipfix import flowmatrix, load_qof_df

def prepare_data(filename, metadata, data):
    zf = ZipFile(BytesIO(data))

    def get_filename_from_zip(endswith):
        for zinfo in zf.filelist:
            if zinfo.filename.endswith(endswith):
                return zinfo.filename

        raise ValueError("No file ending with '{}' in zip file.".format(endswith))

    ipfix_filename = get_filename_from_zip('.ipfix')
    csv_filename = get_filename_from_zip('.csv')

    # load csv data
    es_df = {}
    es_df["ams-0"] = load_es_df(zf.open(csv_filename), "ams", 0)

    cc_df = connmatrix([es_df["ams-0"]], ["ams"], [0])

    # load ipfix data
    qof4_df = {
        'ams-0': load_qof_df(ipfix_filename, open_fn=zf.open, spider_idx=cc_df.index, ipv6_mode=False)
    }
    qof6_df = {
        'ams-0': load_qof_df(ipfix_filename, open_fn=zf.open, spider_idx=cc_df.index, ipv6_mode=True)
    }

    vps    = ["ams"]
    trials = [str(x) for x in [0]]
    labels = ["-".join(l) for l in itertools.product(vps,trials)]

    qq4_df = flowmatrix([qof4_df[label] for label in labels],
                       labels)
    qq4_df["rank"] = cc_df.loc[qq4_df.index]["rank"]
    qq4_df["site"] = cc_df.loc[qq4_df.index]["site"]


    qq6_df = flowmatrix([qof6_df[label] for label in labels],
                         labels)
    qq6_df["rank"] = cc_df.loc[qq6_df.index]["rank"]
    qq6_df["site"] = cc_df.loc[qq6_df.index]["site"]

    qq_df = pd.concat((qq4_df, qq6_df))

    return cc_df, qq_df