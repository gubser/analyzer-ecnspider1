import pandas as pd
import numpy as np
from collections import defaultdict


def create_observation(source, row):
    def none_aware(a, b, op=min):
        if a is not None and b is not None:
            return op(a, b)
        elif a is None:
            return b
        elif b is None:
            return a
        else:
            return None

    time = {
        'from': none_aware(row.get('flowStartMilliseconds_0'), row.get('flowStartMilliseconds_1'), min),
        'to': none_aware(row.get('flowEndMilliseconds_0'), row.get('flowEndMilliseconds_1'), max)
    }

    path = [row.get('sip_0').exploded, '*', row.get('dip_0').exploded]

    # is connectivity ecn dependent?
    if row['ecn0ok']:
        if row['ecn1ok']:
            cond_ecnconn = 'ecn.connectivity.works'
        else:
            cond_ecnconn = 'ecn.connectivity.broken'
    else:
        if row['ecn1ok']:
            cond_ecnconn = 'ecn.connectivity.transient'
        else:
            cond_ecnconn = 'ecn.connectivity.offline'

    conditions = ["ecnspider.basic"]

    value = {
        'ecn': {
            'conn': cond_ecnconn,
            'nego': row['ecnNegotiated_1']
        }
    }

    obs =  {
        'condition': conditions,
        'time': time,
        'path': path,
        'value': value,
        'sources': [source]
    }

    return obs