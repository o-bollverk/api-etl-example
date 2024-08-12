from src.constants.paths import API_BASE_URL, SEVERITY_LEVELS, CVE_JSON_PATH, API_KEY_PATH
import requests
import path
import json
import datetime
import urllib

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
    
def generate_date_ranges(start_date, end_date, interval_months):
    """
    
    Generates date ranges for NIST, which seems to limit longer querieng.
    
    """
    date_ranges = []
    current_start_date = start_date
    while current_start_date < end_date:
        # Calculate the end date for the current range
        next_end_date = current_start_date + datetime.timedelta(days=interval_months * 30)
        if next_end_date > end_date:
            next_end_date = end_date
        
        date_ranges.append((current_start_date, next_end_date))
        
        # Move to the next start date
        current_start_date = next_end_date
    
    return date_ranges


def format_date(date):
    """
    Formats the date to the format suitable for NIST API.
    """
    
    return date.strftime("%Y-%m-%dT%H:%M:%S.000%%2B01:00")

def construct_query_urls(start_date, end_date, interval_months):
    """
    
    Constructs urls for a given range.
    
    """
    date_ranges = generate_date_ranges(start_date, end_date, interval_months)
    query_urls = []
    
    for start, end in date_ranges:
        start_str = format_date(start)
        end_str = format_date(end)
        query_url =  API_BASE_URL + "/?lastModStartDate=" + start_str + "&lastModEndDate=" + end_str
        query_urls.append(query_url)
    
    return query_urls


def get_all_cves_with_start_date(start_date: datetime.datetime, end_date: datetime.datetime, no_of_retries: int = 5) -> None:
    
    headers = {
        
        "apiKey": get_nist_key_from_file()
    }
    
    interval_urls = construct_query_urls(start_date, end_date, interval_months=2)
    
    for i in range(len(interval_urls)):
        url = interval_urls[i]
        
        response = requests.get(url, headers=headers, timeout=180)
        
        response_jsons = []
        
        if response.status_code == 200:         
            response_json = response.json()
            response_jsons.append(response_json)
            
            #dump_to_json(response_json, CVE_JSON_PATH())
            #print("Dumped to json for interval nr " + str(i) + " of " + str(len(interval_urls)))
            
                            
        elif response.status_code == 404:
            if len(response_jsons) > 0:
                dump_to_json(response_jsons, CVE_JSON_PATH())
                print("Dumped to json for interval nr " + str(i) + " of " + str(len(interval_urls)))                
            print("Attempted URL: " + url)
            raise ValueError("Status code 404 on requesting starting from: " + start_date.strftime("%Y-%m-%dT%H:%M:%S.000%%2B01:00"))
        else:
            if len(response_jsons) > 0:
                dump_to_json(response_jsons, CVE_JSON_PATH())
                print("Dumped to json for interval nr " + str(i) + " of " + str(len(interval_urls)))                
            raise ValueError("Unable to request starting from: " + start_date.strftime("%Y-%m-%dT%H:%M:%S.000%%2B01:00"))
    
    dump_to_json(response_jsons, CVE_JSON_PATH())
    print("Dumped to json for interval nr " + str(i) + " of " + str(len(interval_urls)))  


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
            dump_to_json(response_json, CVE_JSON_PATH())
            
        elif response.status_code == 404:

            raise ValueError("Status code 404 on requesting severity level: " + severity_level)
        else:
            raise ValueError("Unable to request severity level: " + severity_level)

    
def dump_to_json(data_dict: dict,  current_path: path.Path):
    with current_path.open("w", encoding="UTF-8") as file:
        json.dump(data_dict, file)
        file.close()



if __name__ == "__main__":
    get_all_cves_with_start_date(
        start_date=datetime.datetime(2021, 10, 1, 0, 0, 0),
        end_date = datetime.datetime(2023, 10, 1, 0, 0, 0))
    
    #get_all_cves_by_severity_rating() # Does not get cases with severity=None
    
    
    
    