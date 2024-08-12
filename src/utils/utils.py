
#import upath
import path
import datetime
from pathlib import Path
import pandas as pd

def get_project_path() -> path.Path:
    """
    Returns either the local project root's universal path
    
    Parameters
    ----------

    Returns
    -------
    UPath
        The path to the project's root directory.
    """

    project_root = path.Path(__file__).absolute().parent.parent.parent

    return project_root


def get_todays_data_dir(subdir: str = "external", delta_in_days: int = 0 ) -> path.Path:
    """
    Create (if doesn't exist) and return the path to the directory of today's files.
    
    If delta is not 0, then the directory is not created (only todays directory is created if not existing)
    Parameters
    
    ----------
    subdir
        Subdirectory of data files. Either "external" or "internal"
    delta_in_days:
        Passed to pandas timedelta to offset the date.
    """
    
    suffix = str((pd.Timestamp.today(tz='Europe/Tallinn') + pd.Timedelta(days = delta_in_days)).date().strftime("%Y-%m-%d"))
    path = get_project_path() / "data" / subdir / suffix

    if not path.exists() and delta_in_days == 0:
        path.mkdir()
    
    return path
