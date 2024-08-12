# Functions for examining db content


import pandas as pd 
import sqlalchemy
import os as os

from sqlalchemy import *
from sqlalchemy.orm import sessionmaker

from src.constants.db_constants import db_connection_str, dbname, CvesSeverity
from src.constants.db_constants import CvesSeverity, CvesScores


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

    return result


def get_scores(db_engine: sqlalchemy.engine) -> pd.DataFrame:

    Session = sessionmaker(bind=db_engine)
    session = Session()

    result = session.query(
                           CvesScores.cve_id, 
                           CvesScores.last_modified, 
                           func.sum(CvesScores.impact_score)).group_by(CvesScores.cve_id, CvesScores.last_modified).all()
    
    session.close()
    
    return result


if __name__ == "__main__":
    
    db_engine = create_engine(db_connection_str  + dbname)
    
    get_severity_level_counts_from_db(db_engine)
    get_scores(db_engine)