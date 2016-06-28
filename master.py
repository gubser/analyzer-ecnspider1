from ptocore.analyzercontext import AnalyzerContext

import dataprep
import analysis

def main():
    ac = AnalyzerContext()

    # complicated way to get data file by file out of hdfs
    files = ac.spark_uploads(["ecnspider1-zip-csv-ipfix"])
    filenames = files.map(lambda x: x[0]).collect()
    for filename in filenames:
        metadata, data = files.lookup(filename)[0]
        upload_id = metadata['_id']
        merged = dataprep.prepare_data(filename, metadata, data)

        for index, row in merged.iterrows():
            obs = analysis.create_observation(upload_id, row)
            # TODO should be done in validator
            obs['analyzer_id'] = ac.analyzer_id
            ac.temporary_coll.insert_one(obs)

if __name__ == "__main__":
    main()