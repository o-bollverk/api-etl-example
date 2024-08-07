
from src.constants.paths import API_BASE_URL, SEVERITY_LEVELS, CVE_JSON_PATH, API_KEY_PATH
import requests
import path
import json
import datetime

def get_nist_key_from_file() -> str:
    """
    Gets NIST api key by reading from a text file on disk.
    
    Returns
    -------
    str
        NIST API key
    """
    
    with API_KEY_PATH.open("r") as file:
        return file.read().strip()
    

def get_all_cves_with_start_date(start_date: datetime.datetime, no_of_retries: int = 5) -> None:
    
    headers = {
        
        "apiKey": get_nist_key_from_file()
    }
    
    start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.000%%2B01:00")
    end_date = "2024-01-01T13:36:00.000%2B01:00"
    get_str = API_BASE_URL + "/?lastModStartDate=" + start_date + "&lastModEndDate=" + end_date
    
    response = requests.get(get_str, headers=headers, timeout=180)
    
    if response.status_code == 200:         
        response_json = response.json()
        dump_to_json(response_json, CVE_JSON_PATH)
        
    
    elif response.status_code == 404:
        raise ValueError("Status code 404 on requesting starting from: " + start_date)
    else:
        raise ValueError("Unable to request starting from: " + start_date)


def get_all_cves_by_severity_rating(no_of_retries: int = 5) -> None:
    """
    Requests all CVS that have a severity along with the rating value
    
    """
    
    headers = {
        # "accept": "text/json",
        "apiKey": get_nist_key_from_file(),
    }
    
    print(get_nist_key_from_file())
    print("Requesting all CVEs by severity rating")
    
    for severity_level in SEVERITY_LEVELS:
        response = requests.get(API_BASE_URL + "?cvssV3Severity=" + severity_level, headers=headers, timeout=180)
        
        if response.status_code == 200:         
            response_json = response.json()
            dump_to_json(response_json, CVE_JSON_PATH)
            print("Dumped to json")
            
        elif response.status_code == 404:
            raise ValueError("Status code 404 on requesting severity level: " + severity_level)
        else:
            raise ValueError("Unable to request severity level: " + severity_level)

    
def dump_to_json(data_dict: dict,  current_path: path.Path):
    with current_path.open("w", encoding="UTF-8") as file:
        json.dump(data_dict, file)
        file.close()



if __name__ == "__main__":
    #get_all_cves_with_start_date(start_date=datetime.datetime(2023, 1, 1, 0, 0, 0))
    get_all_cves_by_severity_rating() # Does not get cases with severity=None
    
    
    
    