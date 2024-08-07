
#import upath
import path
import datetime
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


def get_todays_data_dir(subdir: str = "external") -> path.Path:
    """
    Create (if doesn't exist) and return the path to the directory of today's files.

    Parameters
    ----------
    today
    subdir
        Subdirectory of data files. Either "external" or "internal"
    """

    path = get_project_path() / "data" / subdir / pd.Timestamp.today(tz='Europe/Tallinn').date().strftime("%Y-%m-%d")

    if not path.exists():
        path.mkdir()
    
    return path

def get_previous_data_dir(delta_in_days: int, subdir: str = "external") -> bool:
    """
    Get yesterday's data directory.

    Parameters
    ----------
    today
    subdir
        Subdirectory of data files. Either "external" or "internal"
    """

    path = get_project_path() / "data" / subdir / (pd.Timestamp.today(tz='Europe/Tallinn').date() + pd.Timedelta(days = delta_in_days)).strftime("%Y-%m-%d")
    
    return path
