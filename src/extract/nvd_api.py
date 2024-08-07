
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
    

    # payload = {"curves": curves}
    # headers = {
    #     "accept": "application/json",
    #     "content-type": "application/json",
    #     "Authorization": f"Bearer {access_token}",
    # }
    # response = requests.patch(
    #     os.getenv("NORDPOOL_API_URL_BASE") + "curveorders" + f"/{order_id}", json=payload, headers=headers, timeout=60
    # )
    # return response
#"2023-01-01T00:00:00.0002B01:00"
#"2023-01-01T00:00:00.000%2B01:00"
#"2021-08-04T13:00:00.000%2B01:00"
# CORRECT
# https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2021-08-04T13:00:00.000%2B01:00&lastModEndDate=2021-10-22T13:36:00.000%2B01:00


# https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2021-08-04T13:00:00.000%2B01:00&lastModEndDate=2021-10-22T13:36:00.000%2B01:00
# https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=2023-01-01T00:00:00.000%2B01:00&lastModEndDate=2024-01-01T13:36:00.000%2B01:00


def get_all_cves_with_start_date(start_date: datetime.datetime, no_of_retries: int = 5) -> None:
    
    headers = {
        
        "apiKey": get_nist_key_from_file()
    }
    
    start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.000%%2B01:00")
    end_date = "2024-01-01T13:36:00.000%2B01:00"
    get_str = API_BASE_URL + "/?lastModStartDate=" + start_date + "&lastModEndDate=" + end_date
    
    print(start_date)
    print(get_nist_key_from_file())
    print(get_str)
    
    response = requests.get(get_str, headers=headers, timeout=180)
    
    if response.status_code == 200:         
        response_json = response.json()
        #print(response_json)
        dump_to_json(response_json, CVE_JSON_PATH)
        
        #response_json.dump(CVE_JSON_PATH)
    
    # elif response_json["status"] == 404:
    #     if no_of_retries < 10:
    #         print("Retrying")
    #         get_all_cves_by_severity_rating(no_of_retries + 1)
    
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
        # print(response)
        
        if response.status_code == 200:         
            response_json = response.json()
            #print(response_json)
            dump_to_json(response_json, CVE_JSON_PATH)
            print("Dumped to json")
            
            #response_json.dump(CVE_JSON_PATH)
        
        # elif response_json["status"] == 404:
        #     if no_of_retries < 10:
        #         print("Retrying")
        #         get_all_cves_by_severity_rating(no_of_retries + 1)
        elif response.status_code == 404:
            raise ValueError("Status code 404 on requesting severity level: " + severity_level)
        else:
            raise ValueError("Unable to request severity level: " + severity_level)


    #API_BASE_URL + "cvssV3Severity=" level 
    
def dump_to_json(data_dict: dict,  current_path: path.Path):
    with current_path.open("w", encoding="UTF-8") as file:
        json.dump(data_dict, file)
        file.close()





# def get_nist_access_token() -> str:
#     """
#     Gets access token from authorization API and returns it to be used by other calls
#     See description here: https://nvd.nist.gov/developers/start-here
#     Returns
#     -------
#     str
#         Access token for NIST API
#     """
#     auth_to_encode = f"{os.getenv('NORDPOOL_CLIENT_ID')}:{os.getenv('NORDPOOL_CLIENT_SECRET')}"
#     # auth_to_encode = f"{client_id}:{client_secret}"
#     auth_to_encode_bytes = auth_to_encode.encode("ascii")
#     base64_bytes = base64.b64encode(auth_to_encode_bytes)
#     base64_auth = base64_bytes.decode("ascii")

#     headers = {
#         "accept": "application/json",
#         "Content-type": "application/x-www-form-urlencoded",
#         "Authorization": f"Basic {base64_auth}",
#     }

#     payload = {
#         "grant_type": "password",
#         "scope": "auction_api",
#         "username": os.getenv("NORDPOOL_API_USERNAME"),
#         "password": os.getenv("NORDPOOL_API_PW"),
#     }

#     auth_response = requests.post(os.getenv("NORDPOOL_API_AUTH_URL"), data=payload, headers=headers, timeout=60)
#     if auth_response.status_code != 200:
#         log_authorization_error(auth_response)
#         return None
#     return auth_response.json()["access_token"]

if __name__ == "__main__":
    #get_all_cves_with_start_date(start_date=datetime.datetime(2023, 1, 1, 0, 0, 0))
    get_all_cves_by_severity_rating()
    
    
    
    