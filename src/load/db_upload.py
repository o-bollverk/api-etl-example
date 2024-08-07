# Functions for loading raw json files, performing data checks with pandas, and uploading them
# to a MySQL database.
# Functions for setting up db

import pandas as pd 
import sqlalchemy
import os as os
import numpy as np 
import datetime
import pymysql
import re

from pandas.api.types import is_datetime64_any_dtype as is_datetime

from sqlalchemy import *
# from sqlalchemy import Table, Column, Integer, String, create_engine
#from sqlalchemy import func
#from sqlalchemy import create_engine, text, MetaData

from sqlalchemy.dialects.mysql import insert
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from src.constants.db_constants import db_connection_str, dbname, CvesSeverity
from src.constants.db_constants import Base, CvesSeverity, CvesScores, CvesAttackVectors, CvesFact
from src.utils.utils import get_todays_data_dir, get_previous_data_dir
from src.constants.paths import CVE_PARQUET_PATH, CVE_JSON_PATH




def init_db(db_engine: sqlalchemy.engine) -> None:
    with db_engine.begin() as conn:
        conn.execute(
            text("CREATE DATABASE IF NOT EXISTS nist_analytics")
        )
        conn.execute(
            text("USE nist_analytics") # TODO dbname
        )
        conn.close()

def convert_json_to_parquet(json_file_path: str, output_parquet_file_path: str) -> None:
    """
    Converts the full dump to csv.
    Keep only rows that have a difference in date_modified.
    Otherwise, if there is no data from yesterday, keep all rows.
    
    Parameters
    ----------
    json_file_path
        The path to the json file.
    csv_file_path
        The path to the csv file.
        
    """

    
    df = pd.read_json(json_file_path)
    df["has_v3"] = df.vulnerabilities.apply(lambda x: "cvssMetricV31" in x["cve"]["metrics"].keys())
    
    cve_ids_series_str = df.vulnerabilities.apply(lambda x: x["cve"]["id"])
    cve_ids_series =  cve_ids_series_str.apply(lambda x: int("".join(x.split("-")[1:]))) 
    
    description_series = df.vulnerabilities.apply(lambda x: x["cve"]["descriptions"][0]["value"])
    # TODO limit lenght to higher?
    description_series = description_series.str.slice(0, 499)
    
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
    
    
    last_modified_series = pd.to_datetime(df.vulnerabilities.apply(lambda x: x["cve"]["lastModified"]))
    
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
    
    # TODO 
    if get_previous_data_dir(delta_in_days = -1).joinpath("cve.parquet").exists():
        yesterday_df = pd.read_parquet(get_previous_data_dir(delta_in_days = -1) + "/cve.parquet")
        todays_df = full_df.merge(yesterday_df[["cve_id", "last_modified"]].rename(columns = {"last_modified": "last_modified_yesterday"})
                                , on="cve_id", how="left")
        
        todays_df = todays_df.loc[todays_df.last_modified  > todays_df.last_modified_yesterday, :]
        todays_df.to_parquet(output_parquet_file_path, engine = "pyarrow", compression="snappy") 
        
    else:
        full_df.to_parquet(output_parquet_file_path, engine=  "pyarrow", compression="snappy")
    
    
    
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
        mysql_replace_into(CvesFact, db_engine, cve_fact_df)
        #cve_fact_df.to_sql("cves_fact", db_engine, if_exists="append", index=False)
    except OperationalError as e:
        print(f"Uploading to fact table failed: {e}")
    
    return True


def load_severity_types_to_db(file_path: str, db_engine) -> bool:
    """
    Load data for the severity types table from parquet to db.
    
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
    severity_types_df = df[["severity", "cve_id"]].reset_index().rename(columns = {"index": "id"})
    
    try: 
        #mysql_replace_into("cves_severity", db_engine, severity_types_df)
        mysql_replace_into(CvesSeverity, db_engine, severity_types_df)
        #severity_types_df.to_sql("cves_severity", db_engine, if_exists="append", index=False)
    except OperationalError as e:
        print(f"Uploading to severity types table failed: {e}")
        return False
    
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
    scores_df = df[["cve_id", "impact_score", "exploitability_score"]].reset_index().rename(columns = {"index": "id"})
    #scores_df = scores_df[["id", "cve_id", "impact_score", "exploitability_score"]]
    try: 
        #mysql_replace_into("cves_scores", db_engine, scores_df)
        mysql_replace_into(CvesScores, db_engine, scores_df)
        # scores_df.to_sql("cves_scores", db_engine, if_exists="append", index=False)
    except OperationalError as e:
        print(f"Uploading to scores table failed: {e}")
        return False
    
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
    
    attack_vectors_df = df[["cve_id", "attack_vector"]].reset_index().rename(columns = {"index": "id"})
    
    try: 
        #mysql_replace_into("cves_attack_vectors", db_engine, attack_vectors_df)
        mysql_replace_into(CvesAttackVectors, db_engine, attack_vectors_df)
        #attack_vectors_df.to_sql("cves_attack_vectors", db_engine, if_exists="append", index=False)
    except OperationalError as e:
        print(f"Uploading to attack vectors table failed: {e}")
        return False
    
    return True


def delete_directory_for_day_before_yesterday() -> None:
    """
    Deletes the directory for the day before yesterday.
    """
    
    if get_previous_data_dir(delta_in_days = -2).exists():
        get_previous_data_dir(delta_in_days = -2).rmdir()
        print("Directory deleted from day before yesterday")
    else:
        print("Directory does not exist")


# # https://stackoverflow.com/questions/34661318/replace-rows-in-mysql-database-table-with-pandas-dataframe
# def mysql_replace_into(table_name, db_engine, df):

#     #data_iter = data_iter.tolist()
    
#     with db_engine.connect() as conn:
        
#         table = Table(table_name, metadata, autoload_with=conn)
#         #data = df.to_dict(orient='records')
        
#         keys = df.columns.tolist()
#         data_iter = df.iterrows()
#         data = [dict(zip(keys, row)) for row in data_iter]
        
#         #exit()
        
#         stmt = insert(table).values(data)
#         update_stmt = stmt.on_duplicate_key_update(**dict(zip(stmt.inserted.keys(), 
#                                                 stmt.inserted.values())))

#         conn.execute(update_stmt)
        
#         conn.close()

def mysql_replace_into(orm_class, db_engine, df):
    # Create a session
    Session = sessionmaker(bind=db_engine)
    session = Session()

    try:
        # Get the Core table from the ORM class
        table = orm_class.__table__

        # Prepare the data for insertion
        
        data = df.to_dict(orient = 'records' ) #[row for row in] 
        #data = [dict(zip(keys, row)) for row in data_iter]
        

        # Create an insert statement
        stmt = insert(table).values(data)
        
        # Define the update statement for duplicates
        update_stmt = stmt.on_duplicate_key_update(**{c.name: stmt.inserted[c.name] for c in table.columns})

        # Execute the statement
        with db_engine.connect() as conn:
            conn.execute(update_stmt)

    finally:
        session.close()
        

def all_data_types_are_as_expected(df):
    expected_dtypes_dict = {'cve_id': str,
                            'severity': str,
                            'last_modified': str} 
    print(df.dtypes) #print(df.dtypes.equals(pd.Series(expected_dtypes_dict)))
    
    if df.dtypes.equals(pd.Series(expected_dtypes_dict)):
        return True
    else:
        return False


def get_severity_level_counts_from_db(db_engine: sqlalchemy.engine) -> pd.DataFrame:

    Session = sessionmaker(bind=db_engine)
    session = Session()

    # Perform GROUP BY and COUNT using SQLAlchemy ORM
    result = session.query(CvesSeverity.severity, 
                           func.count(CvesSeverity.id)).group_by(CvesSeverity.severity).all()

    
    for severity, count in result:
        print(f"{severity}: {count}")

    # Close the session
    session.close()


def severity_counts(db_engine: sqlalchemy.engine) -> pd.DataFrame:

    Session = sessionmaker(bind=db_engine)
    session = Session()

    result = session.query(
                           CvesSeverity.severity, 
                           func.count(CvesSeverity.cve_id)).group_by(CvesSeverity.severity).all()
   

    
    for severity, count in result:
        print(f"{severity}: {count}")

    # Close the session
    session.close()


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
    # Load the data
    #os.setevn("PYTHONPATH", ""
    #db_engine = create_engine(db_connection_str)
    #db_engine = create_engine(db_connection_str  + dbname)
    #fact_table_counts(db_engine)
    #exit()
    
    from src.utils.utils import get_todays_data_dir
    
    convert_json_to_parquet(json_file_path = CVE_JSON_PATH,
                            output_parquet_file_path= CVE_PARQUET_PATH
    )
    
    # Check the data types
    #if not all_data_types_are_as_expected(severity_types_df):
    #    raise ValueError("Data types in json are not as expected")
    
    # Create the db engine
    db_engine = create_engine(db_connection_str)
    
    # Initialize the db
    init_db(db_engine)
    
    # Recreate the db engine with the db name
    db_engine = create_engine(db_connection_str  + dbname)
    
    # DROP ALL TABLES
    metadata = Base.metadata
    metadata.drop_all(bind=db_engine)
    
    # Create the data model schemas
    create_data_model_schemas(db_engine)
    
    # Upload the data to the db
    load_cve_and_descriptions_to_db(CVE_PARQUET_PATH, db_engine)
    load_scores_to_db(CVE_PARQUET_PATH, db_engine)
    load_severity_types_to_db(CVE_PARQUET_PATH, db_engine)
    load_attack_vectors_to_db(CVE_PARQUET_PATH, db_engine)
        
    severity_counts(db_engine)

    # get_severity_level_counts_from_db(db_engine)
    