
#import upath
import path
import datetime

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


def get_todays_data_dir(today: datetime.date, subdir: str = "external" ) -> path.Path:
    """
    Create (if doesn't exist) and return the path to the directory of today's files.

    Parameters
    ----------
    today
    subdir
        Subdirectory of data files. Either "external" or "internal"
    """

    path = get_project_path() / "data" / subdir / today.strftime("%Y-%m-%d")

    return path
