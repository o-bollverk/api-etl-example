# Functions for loading raw json files, performing data checks with pandas, and uploading them
# to a MySQL database.
# Functions for setting up db

import pandas as pd 
import sqlalchemy
import os as os

from sqlalchemy import *
# from sqlalchemy import Table, Column, Integer, String, create_engine
#from sqlalchemy import func
#from sqlalchemy import create_engine, text, MetaData

from sqlalchemy.exc import OperationalError

from src.constants.db_constants import db_connection_str, dbname
from src.constants.db_constants import Base
from src.utils.utils import get_todays_data_dir
from src.constants.paths import CVE_PARQUET_PATH, CVE_JSON_PATH


def init_db(db_engine: sqlalchemy.engine) -> None:
    """
    Inits the db.
    # TODO: Needs refactoring so that text() would not be used for security reasons.
    
    Parameters
    ----------
    
    db_engine
        The sqlalchemy engine.
        
    """
    with db_engine.begin() as conn:
        conn.execute(
            text(f"CREATE DATABASE IF NOT EXISTS {dbname}")
        )
        conn.execute(
            text(f"USE {dbname}") 
        )
        conn.close()
        

def convert_json_to_parquet() -> None:
    """
    Converts the full dump to parquet for today.
    Keep only rows that have a difference in date_modified compared to file from yesterday.
    Otherwise, if there is no data from yesterday, keep all rows.
    
    Parameters
    ----------
    json_file_path
        The path to the json file.
    csv_file_path
        The path to the csv file.
        
    """

    df = pd.read_json(CVE_JSON_PATH())
    
    df["has_v3"] = df.vulnerabilities.apply(lambda x: "cvssMetricV31" in x["cve"]["metrics"].keys())
    
    cve_ids_series_str = df.vulnerabilities.apply(lambda x: x["cve"]["id"])
    cve_ids_series =  cve_ids_series_str.apply(lambda x: int("".join(x.split("-")[1:]))) 
    
    description_series = df.vulnerabilities.apply(lambda x: x["cve"]["descriptions"][0]["value"])
    
    # TODO limit lenght to higher?
    description_series = description_series.str.slice(0, 499)
    
    # Variable extraction according to the format provided by NIST API
    severity_series = df.apply(lambda x: x["vulnerabilities"]["cve"]["metrics"]['cvssMetricV31'][0]["cvssData"]["baseSeverity"] 
                                               if x["has_v3"] else 
                                               x["vulnerabilities"]["cve"]["metrics"]['cvssMetricV2'][0]["baseSeverity"], axis = 1)

    attack_vector_series = df.apply(lambda x: x["vulnerabilities"]["cve"]["metrics"]['cvssMetricV31'][0]["cvssData"]["attackVector"] 
                                               if x["has_v3"] else None, axis = 1)
    
    expl_score_series = df.apply(lambda x: x["vulnerabilities"]["cve"]["metrics"]['cvssMetricV31'][0]["exploitabilityScore"]
                                        if x["has_v3"] else 
                                        x["vulnerabilities"]["cve"]["metrics"]['cvssMetricV2'][0]["exploitabilityScore"], axis = 1)
    
    impact_score_series = df.apply(lambda x: x["vulnerabilities"]["cve"]["metrics"]['cvssMetricV31'][0]["impactScore"]
                                        if x["has_v3"] else 
                                        x["vulnerabilities"]["cve"]["metrics"]['cvssMetricV2'][0]["impactScore"], axis = 1)
    
    
    last_modified_series = pd.to_datetime(df.vulnerabilities.apply(lambda x: x["cve"]["lastModified"])).apply(lambda x: x.date())
    
    # Creates a dataframe and does internal type casting that is compatible with the db
    
    full_df = pd.DataFrame({"cve_id": cve_ids_series.astype(int),
                                        "cve_id_str": cve_ids_series_str.astype(str),
                                        "description": description_series.astype(str),
                                        "severity": severity_series.astype(str),
                                        "attack_vector": attack_vector_series.astype(str),
                                        "exploitability_score": expl_score_series.astype(float),
                                        "impact_score": impact_score_series.astype(float),
                                        "has_v3" : df.has_v3,
                                        "last_modified": last_modified_series
                                        })
    
    yesterdays_parquet_path = CVE_PARQUET_PATH(delta_in_days = -1)
    
    if yesterdays_parquet_path.exists():
        yesterday_df = pd.read_parquet(yesterdays_parquet_path)
        
        todays_df = full_df.merge(yesterday_df[["cve_id", "last_modified"]].rename(columns = {"last_modified": "last_modified_yesterday"})
                                , on="cve_id", how="left")
        
        todays_df = todays_df.loc[todays_df.last_modified  > todays_df.last_modified_yesterday, :]
        
        todays_df.to_parquet(CVE_PARQUET_PATH(), engine = "pyarrow", compression="snappy") 
        
    else:
        # If there is no data from yesterday, keep all rows ( assumes then that this the initial data being loaded)
        full_df.to_parquet(CVE_PARQUET_PATH(), engine=  "pyarrow", compression="snappy")
    
    
    
def load_cve_and_descriptions_to_db(file_path: str, db_engine) -> bool:
    """
    Load data for the fact table from parquet to db.
    
    Parameters
    ----------
    file_path
        The path to the parquet file.
    
    Returns
    -------
    pd.DataFrame
        The DataFrame containing the parquet data.
    """
    
    df = pd.read_parquet(file_path)
    cve_fact_df = df[[ "cve_id", "cve_id_str", "description"]]
    
    try: 
        cve_fact_df.to_sql("cves_fact", db_engine, if_exists="append", index=False)
    except OperationalError as e:
        print(f"Uploading to fact table failed: {e}")
    
    print("Appended " +  str(cve_fact_df.shape[0]), " rows into cves_fact")
    
    return True


def load_severity_types_to_db(file_path: str, db_engine) -> bool:
    """
    Load data for the severity table from parquet to db.
    
    Parameters
    ----------
    file_path
        The path to the parquet file.
    
    Returns
    -------
    bool
        True if the operation was successful, False otherwise.
    """
    
    df = pd.read_parquet(file_path)
    severity_types_df = df[["severity", "cve_id", "last_modified"]].reset_index().rename(columns = {"index": "id"})
    
    try: 
        severity_types_df.to_sql("cves_severity", db_engine, if_exists="append", index=False)
    except OperationalError as e:
        print(f"Uploading to severity table failed: {e}")
        return False
    
    print("Appended " +  str(severity_types_df.shape[0]), " rows into cves_severity")
    return True

def load_scores_to_db(file_path: str, db_engine) -> bool:
    """
    Load data for the scores table from parquet to db.
    
    Parameters
    ----------
    file_path
        The path to the parquet file.
    
    Returns
    -------
    bool
        True if the operation was successful, False otherwise.
    """
    
    df = pd.read_parquet(file_path)
    scores_df = df[["cve_id", "impact_score", "exploitability_score", "last_modified"]] .reset_index().rename(columns = {"index": "id"})

    try: 
        scores_df.to_sql("cves_scores", db_engine, if_exists="append", index=False)
    except OperationalError as e:
        print(f"Uploading to scores table failed: {e}")
        return False
    
    print("Appended " +  str(scores_df.shape[0]), " rows into cves_scores")
    return True

def load_attack_vectors_to_db(file_path: str, db_engine) -> bool:
    """
    Load data for the attack vectors table from parquet to db.
    
    Parameters
    ----------
    file_path
        The path to the parquet file.
    
    Returns
    -------
    bool
        True if the operation was successful, False otherwise.
    """
    
    df = pd.read_parquet(file_path)
    df = df.loc[df.has_v3,:] # AV only provided for v3
    
    attack_vectors_df = df[["cve_id", "attack_vector", "last_modified"]].reset_index().rename(columns = {"index": "id"})
    
    try: 
        attack_vectors_df.to_sql("cves_attack_vectors", db_engine, if_exists="append", index=False)
    except OperationalError as e: 
        print(f"Uploading to attack vectors table failed: {e}")
        return False
    
    print("Appended " +  str(attack_vectors_df.shape[0]), " rows into cves_attack_vectors")
    return True


def delete_directory_for_day_before_yesterday() -> None:
    """
    Deletes the directory for the day before yesterday.
    """
    
    if get_todays_data_dir(delta_in_days = -2).exists():
        try: 
            get_todays_data_dir(delta_in_days = -2).rmdir()
            print("Directory deleted from day before yesterday")
        except OSError as e:
            print(f"Deletion of directory failed for day before yesterday: {e}")
    else:
        print("Directory from day before yesterday does not exist")



def create_data_model_schemas(db_engine: sqlalchemy.engine) -> bool:
    """
    Creates tables in the db.
    
    Parameters
    ----------
    db_engine
        The sqlalchemy engine.
        
    Returns
    -------
    bool
        True if successful.
    """
   
    try: 
         Base.metadata.create_all(db_engine)
    except OperationalError as e:
        print(f"Creating tables failed: {e}")
    
    return True


if __name__ == "__main__":
    
    # Create the db engine
    db_engine = create_engine(db_connection_str)
    
    # Initialize the db
    init_db(db_engine)
    
    # Recreate the db engine with the db name
    db_engine = create_engine(db_connection_str  + dbname)
    
    convert_json_to_parquet()
    
    # Create the db engine
    db_engine = create_engine(db_connection_str)
    
    # Initialize the db
    init_db(db_engine)
    
    # Recreate the db engine with the db name
    db_engine = create_engine(db_connection_str  + dbname)
    
    # DROP ALL TABLES
    metadata = Base.metadata
    
    # Create the data model schemas
    create_data_model_schemas(db_engine)
    
    metadata.drop_all(bind=db_engine)
        
    # Upload the data to the db
    load_cve_and_descriptions_to_db(CVE_PARQUET_PATH(), db_engine)
    
    load_scores_to_db(CVE_PARQUET_PATH(), db_engine)
    
    load_severity_types_to_db(CVE_PARQUET_PATH(), db_engine)
    
    load_attack_vectors_to_db(CVE_PARQUET_PATH(), db_engine)

    # Delete the directory for the day before yesterday
    
    # delete_directory_for_day_before_yesterday()