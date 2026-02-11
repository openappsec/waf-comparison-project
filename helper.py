import sys
import urllib.parse
import zipfile
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from tqdm import tqdm
import requests

from config import DATA_SETS_PATH, LEGITIMATE_URL_PATH, MALICIOUS_URL_PATH, LEGITIMATE_PATH, MALICIOUS_PATH, \
    WAFS_CONFIG_FILE_NAME, DB_PATH, conn
from logger import log


def load_json_file(file_path: str | Path) -> Any:
    """
    Load a JSON file from the given path.

    Args:
        file_path (str | Path): Path to the JSON file.
    Returns:
        Any: Parsed JSON data.
    """
    try:
        with open(file_path, 'r') as _file:
            return json.load(_file)
    except Exception as e:
        log.error(f"Could not load JSON file {file_path}: {e}")
        sys.exit()


def _malicious_data_set_preparation() -> None:
    """
    ***Not in use***
    Download the original mgm files and convert them to the tool format.
    """
    malicious_data = f"https://api.github.com/repos/openappsec/mgm-web-attack-payloads/contents/nuclei/payloads"
    test_names = requests.get(malicious_data)
    for test_name in test_names.json():
        files = requests.get(test_name['url'])
        true_positives_download_url = [x['download_url'] for x in files.json() if x['name'] == 'true-positives.txt'][0]
        true_positives_data = requests.get(true_positives_download_url).text.splitlines()
        test_set_content = [{
            "method": "GET",
            "url": f"/?p={urllib.parse.quote(line).replace('%25', '%')}",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                "Connection": "close"
            },
            "data": "",
        } for line in true_positives_data]
        test_set_content.extend([{
            "method": "POST",
            "url": "/",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Connection": "close"
            },
            "data": f"p={urllib.parse.quote(line).replace('%25', '%')}",
        } for line in true_positives_data])
        MALICIOUS_PATH.mkdir(exist_ok=True)
        with open((MALICIOUS_PATH / test_name['name']).with_suffix('.json'), 'w') as _file:
            json.dump(test_set_content, _file)


def zip_extract(file_to_extract: str) -> None:
    """
    Extract zip files to the DATA_SETS_PATH directory.

    Args:
        file_to_extract (str): Path to the zip file.
    """
    with zipfile.ZipFile(file_to_extract, 'r') as zip_ref:
        zip_ref.extractall(DATA_SETS_PATH)


def download_file(url: str, _progress_bar_name: str) -> None:
    """
    Download a file from a URL and extract it if it's a zip file.

    Args:
        url (str): URL to download.
        _progress_bar_name (str): Name for the progress bar.
    """
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc=f"Downloading {_progress_bar_name}")
    file_path = DATA_SETS_PATH / url.split("/")[-1]
    with open(file_path, 'wb') as file:
        for data in response.iter_content(block_size):
            progress_bar.update(len(data))
            file.write(data)
    progress_bar.close()
    zip_extract(file_path)


def prepare_data() -> None:
    """
    Prepare malicious and legitimate data sets by downloading and extracting if not already present.
    """
    if MALICIOUS_PATH.exists():
        log.debug("Malicious Data Set Already Loaded")
    else:
        download_file(MALICIOUS_URL_PATH, "Malicious Data set")
        log.info("Malicious Data Set Preparation Completed.")
    if LEGITIMATE_PATH.exists():
        log.debug("Legitimate Data Set Already Loaded")
    else:
        download_file(LEGITIMATE_URL_PATH, "Legitimate Data set")
        log.info("Legitimate Data Set Preparation Completed.")


def send_request(_method: str, _url: str, _headers: Optional[Dict[str, str]] = None, _data: Any = None,
                 _timeout: float = 0.5) -> List[Any]:
    """
    Send an individual HTTP request and return the status code and whether the request was blocked.

    Args:
        _method (str): HTTP method (GET, POST, etc.).
        _url (str): URL to send the request to.
        _headers (Optional[Dict[str, str]]): HTTP headers.
        _data (Any): Request body data.
        _timeout (float): Timeout for the request in seconds.
    Returns:
        List[Any]: [status_code, blocked (bool)].
    """
    if _headers:
        for key in list(_headers.keys()):
            if key.lower() == "host":
                _headers.pop(key)
    attempts = 0
    while attempts < 3:
        try:
            res = requests.request(_method, url=_url, headers=_headers, data=_data, timeout=_timeout)
            return [
                res.status_code,
                "The requested URL was rejected. Please consult with your administrator." in res.text
                or res.status_code == 403
            ]
        except Exception:
            attempts += 1
            time.sleep(0.1 * attempts)
    return [0, False]


def is_table_exists(_table_name: str) -> bool:
    """
    Check if a table exists in the database.

    Args:
        _table_name (str): Name of the table to check.
    Returns:
        bool: True if table exists, False otherwise.
    """
    with conn.connect() as connection:
        result = connection.execute(
            text("SELECT 1 FROM information_schema.tables WHERE table_schema = 'main' AND table_name = :table_name"),
            {"table_name": _table_name}
        )
        exists = result.fetchone() is not None
    return exists


def drop_table_if_exists(_table_name: str) -> None:
    """
    Drop a table if it exists in the database.

    Args:
        _table_name (str): Name of the table to drop.
    """
    if is_table_exists(_table_name):
        with conn.connect() as connection:
            connection.execute(text(f"DROP TABLE {_table_name}"))
            connection.commit()  # commit changes to the DB
        log.debug(f"Starting New test, table {_table_name} was dropped")


def load_wafs_config() -> Dict[str, str]:
    """
    Load the WAFs configuration from the JSON file.

    Returns:
        Dict[str, str]: The WAFs configuration as a dictionary.
    """
    try:
        with open(DB_PATH / WAFS_CONFIG_FILE_NAME, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        log.error(f"Could not load WAFs config: {e}")
        sys.exit()


def print_table(title: str, table: str) -> None:
    """
    Print a table to the console using the tabulate, style it with a centered title, and print it using logger.
    Centers the title based on the table width.

    Args:
        title (str): Title of the table.
        table (str): Data to be printed in the table.
    """
    table_lines = table.splitlines()
    table_width = len(table_lines[0])
    centered_title = title.center(table_width)
    log.info(centered_title)

    for line in table_lines:
        log.info(line)
