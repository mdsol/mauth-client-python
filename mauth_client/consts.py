import re

AUTH_HEADER_DELIMITER = ";"

MWS_TOKEN = "MWS"
X_MWS_AUTH = "X-MWS-Authentication"
X_MWS_TIME = "X-MWS-Time"
X_MWS_AUTH_PATTERN = re.compile(r"\A([^ ]+) *([^:]+):([^:]+)\Z")

MWSV2_TOKEN = "MWSV2"
MCC_AUTH = "MCC-Authentication"
MCC_TIME = "MCC-Time"
MWSV2_AUTH_PATTERN = re.compile(r"({}) ([^:]+):([^;]+){}".format(MWSV2_TOKEN, AUTH_HEADER_DELIMITER))
