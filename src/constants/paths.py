from src.utils.utils import get_todays_data_dir
import pandas as pd
import path

def CVE_JSON_PATH(delta_in_days = 0) -> path.Path:
    return get_todays_data_dir(delta_in_days = delta_in_days) / "cve.json"

def CVE_PARQUET_PATH(delta_in_days = 0) -> path.Path:
    return get_todays_data_dir(delta_in_days = delta_in_days) / "cve.parquet"

API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
API_KEY_PATH = path.Path("/Users/oliverbollverk/nist_key/api_key.txt")