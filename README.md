# api-etl-example

This projects introduces a solution whereby data is pulled from an extrnal api, stored on disk, uploaded to database, and made accessible via a Django API.

The following points summarise the workflow:
1) Having obtained a key from NIST, data about CVIS is pulled and stored into json files
2) Data from JSON is read with pandas and with unnecessary columns removed. This is written down as parquet. Only rows with a newer date_modified value, in comparison to yesterday's parquet file, are stored.
3) The parquet files are read in by seperate functions, each for a table in the database. The data is uploaded to the db using pandas sql api / sqlalchemy
4) A Django API makes the uploaded data acessible. This utilizes Django ORM

Code structure wise:
- src/constants: contains paths for json and parquet files, database schema definition with declerative base classes 
- src/extract: functions for pulling data with nvd_api
- src/load: functions for setting up DB, loading parquet files to it, doing some basic queries with sqlalchemy
- src/utils: functions for handling dates, current project path
- cve_api: a directory and filestructure corresponding to a Django app. Contains models.py, views.py, urls.py, etc. Defines the types of queries supported by API, the links by which the results are accessible.
- main.py: does all steps required to have data in DB.

Additional notes:
- A main fact table contains only the cve_id and description
- Other tables are related by a foregin key, that is an integer representation of cve_id. 
- Values in tables are uploaded each day on the data that is stored for that day in the parquet file. This will only contain rows that have a higher date_modified value in the raw json , compared to the raw json of yesterday. This avoids storing the last_modified column in the database, and this approach would ensure that only the records with changes are used to update/insert values. The downside is that the full json is dumped each day. A seperate function is provided for deleting the json file two days ago.
- A seperate parquet and json option may be heavy on the disk side at times, but is useful for maintaing a stable flow, as parquet will give any errors if data types have issues.
- Current approach is to pull data for different severity levels in a loop, to aviod overloading the API. 