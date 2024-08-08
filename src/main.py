from src.extract.nvd_api import get_all_cves_with_start_date, get_all_cves_by_severity_rating
from src.load.db_upload import *
from src.constants.paths import CVE_JSON_PATH, CVE_PARQUET_PATH

def main():
    
    # Get data  - dump json
    get_all_cves_by_severity_rating()
    
    # Convert to parquet: 
    convert_json_to_parquet(json_file_path = CVE_JSON_PATH,
                            output_parquet_file_path= CVE_PARQUET_PATH
    )
    
    # Create the db engine
    db_engine = create_engine(db_connection_str)
    
    # Initialize the db
    init_db(db_engine)
    
    # Recreate the db engine with the db name
    db_engine = create_engine(db_connection_str  + dbname)
    
    ######### DROP ALL TABLES #######
    metadata = Base.metadata
    metadata.drop_all(bind=db_engine) # Drop all tables
    
    # Create the data model schemas
    create_data_model_schemas(db_engine)
    
    # Upload the data to the db
    load_cve_and_descriptions_to_db(CVE_PARQUET_PATH, db_engine)
    load_scores_to_db(CVE_PARQUET_PATH, db_engine)
    load_severity_types_to_db(CVE_PARQUET_PATH, db_engine)
    load_attack_vectors_to_db(CVE_PARQUET_PATH, db_engine)
    
    # Check output 
    
    severity_counts(db_engine)
    