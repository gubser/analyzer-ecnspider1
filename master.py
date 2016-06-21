from ptocore.analyzercontext import AnalyzerContext

from dataprep import prepare_data

def main():
    ac = AnalyzerContext()

    # complicated way to get data file by file out of hdfs
    files = ac.spark_uploads(["ecnspider1-zip-csv-ipfix"])
    filenames = files.map(lambda x: x[0]).collect()
    for filename in filenames:
        metadata, data = files.lookup(filename)[0]
        merged = prepare_data(filename, metadata, data)

if __name__ == "__main__":
    main()