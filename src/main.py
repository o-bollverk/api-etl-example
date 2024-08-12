from src.extract.nvd_api import get_all_cves_with_start_date, get_all_cves_by_severity_rating
from src.load.db_upload import *
from src.constants.paths import CVE_JSON_PATH, CVE_PARQUET_PATH
from src.examine.examine import get_scores, get_severity_level_counts_from_db
import datetime

def main():
    
    # Get data  - dump json
    get_all_cves_with_start_date(
        start_date=datetime.datetime(2021, 10, 1, 0, 0, 0),
        end_date = datetime.datetime(2023, 10, 1, 0, 0, 0))
    
    # Convert to parquet: 
    convert_json_to_parquet()
    
    # Create the db engine
    db_engine = create_engine(db_connection_str)
    
    # Initialize the db
    init_db(db_engine)
    
    # Recreate the db engine with the db name
    db_engine = create_engine(db_connection_str  + dbname)
    
    # Create the data model schemas
    create_data_model_schemas(db_engine)
    
    metadata = Base.metadata
    
    ######### DROP ALL TABLES #######
    ##### ADJUST THIS TO DROP ALL #####
    
    # metadata.drop_all(bind=db_engine) # Drop all tables    
    
    # Upload the data to the db for today
    load_cve_and_descriptions_to_db(CVE_PARQUET_PATH(), db_engine)
    load_scores_to_db(CVE_PARQUET_PATH(), db_engine)
    load_severity_types_to_db(CVE_PARQUET_PATH(), db_engine)
    load_attack_vectors_to_db(CVE_PARQUET_PATH(), db_engine)
    
    # Check output 
    
    counts = get_severity_level_counts_from_db(db_engine)
    scores = get_scores(db_engine)
    
    print(counts[:5])
    print(scores[:5])
    
    
if __name__ == "__main__":
    main()