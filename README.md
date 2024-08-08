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

## Environment setup

### 1) Pull the git repo

```bash

git clone https://github.com/o-bollverk/api-etl-example.git

```

### 2) Python environment setup

Setup the python environment with venv.
To do this, navigate to the project directory, and run:

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt 
```

### 3) NIST credentials setup
Get your api key as an email link from NIST, by following these instructions:
https://nvd.nist.gov/developers/request-an-api-key
Once the submission is done, you should receive a key as a link on your email.
Save the contents of the key to a file on your disk as a txt file. 
Replace the value of API_KEY_PATH in the file src.constants.paths with where you saved your key.

### 4) Mysql db setup
For Mac users:
https://www.geeksforgeeks.org/how-to-install-mysql-on-macos/

Edit the file src/constants/db_constants for your database user and database name.
<b>The default example is with a root user that is not recommended.<b>

## Pulling the data
### Standalone option for just pulling and dumping the data.

For pulling the data, activate the python environment and set the pythonpath to the directory in the shell. With a conda or poetry setup, this could be avoided in the configuration file, but in case of using venv, the most straightforward way is to set the global PYTHONPATH variable. For instance:

```bash
source venv/bin/activate
export PYTHONPATH=/Users/yourname/api_task
```

And now run

```bash
python src/extract/nvd_api.py
```

This will run the function

```python
get_all_cves_by_severity_rating()
```

This will pull data to the project directory under /data/extetrnal/YYYY-MM-DD
The directory will have the name of today's date.


### How the pulling works.

Data pulling will currently extract data for each severity level, combine it, and dump into a single json file. 


## Setting up db

Database design is the following and consist of the following tables:
1) Fact table, containg only the cve_id and description columns. Changes here are not expected to occur as the description of a particular cve is unlikely to change. The primary key of the table is an integer representation of cve_id.
2) Severity table. This table contains info on the severity levels for a particular cve_id. It is linked by a foreign key relation to the main table via the integer cve_id column. It is updated whenever the date modified value is updated. 
3) Scores table. This table contains the exploitability and impact score values. It is linked by a foreign key relation to the main table via the integer cve_id column. It is updated whenever the date modified value is updated. 
4) Attack vector table. It is linked by a foreign key relation to the main table via the integer cve_id column. It is updated whenever the date modified value is updated

These tables enable to answer questions 1, 3, 4 and 5. Using an integer representation of cve_id is likely to speed up queries. The choice to use mysql is for basic reproducibility, to avoid a more complex postgres setup for instance.

Tables are created with the function

```python
create_data_model_schemas(db_engine)
```

## Loading data to db

Loading data to db is performed by seperate functions 

```python
convert_json_to_parquet()

# Upload the data to the db
load_cve_and_descriptions_to_db(CVE_PARQUET_PATH, db_engine)
load_scores_to_db(CVE_PARQUET_PATH, db_engine)
load_severity_types_to_db(CVE_PARQUET_PATH, db_engine)
load_attack_vectors_to_db(CVE_PARQUET_PATH, db_engine)

```

In converting json to parquet, the following steps are done:
- Only the relevant fields in the json are extracted
- Data type casting is done. Last modified value in the json is parsed as a pandas datetime column.
- V3 fields data is extracted if v2 is unavaliable

Regarding loading data;
- For attack vector data, only rows with has_v3=True are read in from parquet

## Full workflow for database setup.

The main.py script performs all steps from data loading, dumping to json, setting up the tables in the database, converting to parquet and populating the tables.

## Using the Django API

### Setting up django server
To run the django api, navigate to cve_api.
In case of any changes, do migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

And start the Django API with 

```bash
python manage.py runserver
```
This will start the Django server on the default host.


### Getting results from the server

The API links work in the following way:
1) Return all cve_ids: http://127.0.0.1:8000/custom_api/cves/
2) Get the count of all cve_ids per severity level: http://127.0.0.1:8000/custom_api/cves/severity_aggregation/

3) Get the cve_ids with top 10 impact scores: http://127.0.0.1:8000/custom_api/cves/impact_aggregation/

4) Get the cve_ids with top 10 exploitability scores

http://127.0.0.1:8000/custom_api/cves/expl_aggregation/

5) Get top 10 attack vectors used

http://127.0.0.1:8000/custom_api/cves/attack_vector_aggregation/

