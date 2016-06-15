from ptocore.analyzercontext import AnalyzerContext

import tarfile

ac = AnalyzerContext()

max_action_id, timespans = ac.sensitivity.basic()

rawdata = ac.spark_uploads(max_action_id, timespans)

