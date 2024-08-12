# api-etl-example

This projects introduces a solution whereby data is pulled from the National Vulnerability Database extrnal api (NIST: https://nvd.nist.gov/developers/vulnerabilities), stored on disk, uploaded to database, and made accessible via Django.

The following points summarise the workflow:
1) Having obtained a key from NIST, data about CVEs is pulled and stored into json files.
2) Json files are read with pandas and with unnecessary columns removed, and written down as parquet. Only rows with a newer date_modified value, in comparison to yesterday's parquet file, are stored.
3) The parquet files are read in by seperate functions, each for a table in the database. The data is uploaded to the db using pandas sql api / sqlalchemy
4) A Django API makes the uploaded data acessible. This utilizes Django ORM. 

Code structure wise:
- src/constants: contains paths for json and parquet files, database schema definition with declerative base classes 
- src/extract: functions for pulling data with nvd_api
- src/load: functions for setting up DB, loading parquet files to it, doing some basic queries with sqlalchemy
- src/utils: functions for handling dates, current project path
- src/examine: functions for pulling data from db for some basic aggregation with python, to check that data was inserted properly 
- cve_api: a directory and filestructure corresponding to a Django app. Contains models.py, views.py, urls.py, etc. Defines the types of queries supported by API, the links by which the results are accessible.
- main.py: does all steps required to have data in DB.

Before detailed documentation on functions, modules and database solutions, here are some key ideas in summary:

Regarding database choice:
- A mysql database is chosen for its simple setup. This is far from an ideal choice. The preferred setup would be cloud based object storage (such as S3) with parquet files, and no database.
- The schema and column design follows the principle of a fact table, and seperate tables, which are designed according to the questions about the data. 
- There is a more pythonic level way of defining schemas with sqlalchemy and mysql db . Sqlalchemy declerative base is used to define the table columns in src/constants/db_constants.py. 

Regarding API choice:
- Django is chosen as it is convient to setup. The models.py, views.py logic seems to align nicely with sqlalchemy.
- Django ORM supports doing operations over several tables, when relations are correctly defined. This ORM backend is quite well optimised.
- Downside is probably that there is multiple definitions of table names, along with inner django alises of table names, correct configuration of relations in models.py can be cumbersome. 

Regarding pipeline executability:
- Pipeline is ran from a main.py script and meant to be executed daily.
- Updates to the database are done by appending and storing the modified date of the CVE.
- Parquet files are saved for changes only, so it should be ready to receive new data. 
- The downside is that the full json is dumped each day. A seperate function is provided for deleting the json file two days ago.
- Get command from NIST API is such that it pulls data in two month intervals, to avoid overloading the API. Might still give some errors.

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
<b> The default example is with a root user that is not recommended.</b>

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
    get_all_cves_with_start_date(
        start_date=datetime.datetime(2021, 10, 1, 0, 0, 0),
        end_date = datetime.datetime(2023, 10, 1, 0, 0, 0))
```

This will pull data to the project directory under /data/extetrnal/YYYY-MM-DD
The directory will have the name of today's date. Dates are configurable.


### How the pulling works.

Data pulling will currently extract data for two months, store it in memory and then dump all of the period data into a single json file.


## Setting up db

Database design is the following and consist of the following tables:
1) Fact table, containg only the cve_id and description columns. Changes here are not expected to occur as the description of a particular cve is unlikely to change. The primary key of the table is an integer representation of cve_id.
2) Severity table. This table contains info on the severity levels for a particular cve_id. It is linked by a foreign key relation to the main table via the integer cve_id column. New rows are appended here, and added, only when the date modified is observed to greater than the one that is in the raw dump from yesterday.
3) Scores table. This table contains the exploitability and impact score values. It is linked by a foreign key relation to the main table via the integer cve_id column. New rows are appended here, and added, only when the date modified is observed to greater than the one that is in the raw dump from yesterday.
4) Attack vector table. It is linked by a foreign key relation to the main table via the integer cve_id column. New rows are appended here, and added, only when the date modified is observed to greater than the one that is in the raw dump from yesterday.

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
load_cve_and_descriptions_to_db(CVE_PARQUET_PATH(), db_engine)
load_scores_to_db(CVE_PARQUET_PATH(), db_engine)
load_severity_types_to_db(CVE_PARQUET_PATH(), db_engine)
load_attack_vectors_to_db(CVE_PARQUET_PATH(), db_engine)

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


### API notes

cve_api/cve_api/db_router.py contains functions that enable migrations, etc.
cve_api/cve_api/settings.py  is a standard Django settings file. NB! For a db user with password, password definition should be set here. Also, a proper django key should be generated as per official documentation. 
cve_api/cve_api/views.py define the ORM logic for linking database tables, aggregating the results and returning the results
cve_api/cve_api/models.py defines the core logic of the db model for Django ORM. Foreign key relations need to be defined here for Django and exact alias-es used. Default value for last_modified is defined here (when missing). Field types are defined seperately here as well.


### Getting results from the server

The API links work in the following way:

1) Return all cve_ids: http://127.0.0.1:8000/custom_api/cves/
This endpoint supports the exact choice of cve_id. For instance: http://127.0.0.1:8000/custom_api/cves/?cve_id=CVE-2017-1000378
Should give the output

```python
    {
        "cve_id": 20171000378,
        "cve_id_str": "CVE-2017-1000378",
        "description": "The NetBSD qsort() function is recursive, and not randomized, an attacker can construct a pathological input array of N elements that causes qsort() to deterministically recurse N/4 times. This allows attackers to consume arbitrary amounts of stack memory and manipulate stack memory to assist in arbitrary code execution attacks. This affects NetBSD 7.1 and possibly earlier versions."
    }
```
The cve_id_str is the standard cve_id as an integer representation.
The cve_id field is the inner cve_id that is used in the database for faster quering (integer key)
The description is a truncated description to 500 characters of the corresponding vulnerability.

All of the following endpoints support setting a minimum date to consider for aggregation.

2) Get the count of all cve_ids per severity level: http://127.0.0.1:8000/custom_api/severity/ 
By default, aggregation is provided by date_modified and severity level. 
Since rows are appended to the database, the date modified parameter will enable to provide the aggregation values at a given date.

http://127.0.0.1:8000/custom_api/cves/severity/?min_date=2023-05-01

For instance, if a the cve CVE-2017-1000378 is considered "LOW" with a date modified of 2023-10-01, but then is updated to be "HIGH" on 2024-11-01,
the aggregation will provide the aggregates to reflect the distribution as of both dates, and can therefore be used to get historical metrics. 

3) Get the cve_ids with top 10 impact scores: http://127.0.0.1:8000/custom_api/cves/impact/ 

The top output might look something like this:
```python
    {
        "cveseverity__last_modified": "2023-11-07",
        "cveseverity__severity": "HIGH",
        "severity_count": 163
    },
```

Followed by all combinations of severity levels and last_modified values.

4) Get the cve_ids with top 10 exploitability scores http://127.0.0.1:8000/custom_api/cves/expl/ 

5) Get top 10 attack vectors used http://127.0.0.1:8000/custom_api/cves/attackvec/ 
