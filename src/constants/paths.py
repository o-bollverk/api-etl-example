
#import paths

from src.utils.utils import get_todays_data_dir
import datetime
import pandas as pd
import path

CVE_JSON_PATH = get_todays_data_dir(today =  pd.Timestamp.today(tz='Europe/Tallinn').date()) / "cve_" + datetime.datetime.now().strftime("YYY-MM-DD:HH-MM-SS") + ".json"
API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
API_KEY_PATH = path.Path("/Users/oliverbollverk/nist_key/api_key.txt")