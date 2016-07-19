from ptocore.analyzercontext import AnalyzerContext
from ptocore import sensitivity

import dataprep
import analysis
from pymongo.operations import InsertOne
from itertools import chain

def grouper(iterable, count):
    iterator = iter(iterable)
    while True:
        lst = []
        try:
            for index in range(count):
                lst.append(next(iterator))
        except StopIteration:
            pass
        if len(lst) > 0:
            yield lst
        else:
            break

def main():
    ac = AnalyzerContext()

    max_action_id, upload_ids = sensitivity.direct(ac.action_set)
    # analyze one upload per run
    upload_ids = [upload_ids[0]] if len(upload_ids) > 0 else []
    print("running it with: ", max_action_id, upload_ids)
    ac.set_result_info_direct(max_action_id, upload_ids)

    # complicated way to get data file by file out of hdfs
    files = ac.spark_uploads_direct()
    filenames = files.map(lambda x: x[0]).collect()
    for filename in filenames:
        metadata, data = files.lookup(filename)[0]
        upload_id = metadata['_id']
        merged = dataprep.prepare_data(filename, metadata, data)

        for group in grouper(merged.iterrows(), 1000):
            bulk = []
            for _, row in group:
                obsns = analysis.create_observations(upload_id, row)

                for obs in obsns:
                    # TODO should be done in validator
                    obs['analyzer_id'] = ac.analyzer_id

                    bulk.append(InsertOne(obs))

            ac.temporary_coll.bulk_write(bulk)

if __name__ == "__main__":
    main()