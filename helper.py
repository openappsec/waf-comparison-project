from colorlog import ColoredFormatter
import urllib.parse
import requests
import logging
import zipfile
import json
import time

from sqlalchemy import MetaData, Table
from tqdm import tqdm

from config import DATA_PATH, LEGITIMATE_URL_PATH, MALICIOUS_URL_PATH, LEGITIMATE_PATH, MALICIOUS_PATH, engine

LOG_LEVEL = logging.DEBUG
LOGFORMAT = "  %(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(message)s%(reset)s"
logging.root.setLevel(LOG_LEVEL)
formatter = ColoredFormatter(LOGFORMAT)
stream = logging.StreamHandler()
stream.setLevel(LOG_LEVEL)
stream.setFormatter(formatter)
log = logging.getLogger('pythonConfig')
log.setLevel(LOG_LEVEL)
log.addHandler(stream)


def load_data(_log_file):
    """
    Load each data set as json file
    """
    # Load the data
    with open(_log_file) as _file:
        return json.load(_file)


def _MaliciousDataSetPreparation():
    """
    ***Not in use***
    This function download the original mgm files and convert it to the tool format
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


def zip_extract(file_to_extract):
    """
    Extract zip files
    """
    with zipfile.ZipFile(file_to_extract, 'r') as zip_ref:
        zip_ref.extractall(DATA_PATH)


def download_file(url, _progress_bar_name):
    response = requests.get(url, stream=True)

    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024  # 1 KB
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True,desc=f"Downloading {_progress_bar_name}")

    file_path = DATA_PATH / url.split("/")[-1]

    # Download the data set in zip format
    with open(file_path, 'wb') as file:
        for data in response.iter_content(block_size):
            progress_bar.update(len(data))
            file.write(data)

    progress_bar.close()

    # Extract zip data set
    zip_extract(file_path)

def prepare_data():
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


def sendRequest(_method, _url, _headers=None, _data=None, _timeout=0.5) -> [int, bool]:
    """
    Send individual request, returns the status code and if the request was blocked
    """

    # Delete host header in order for requests to generate it automatically
    if _headers and "Host" in _headers:
        _headers.pop("Host")

    attempts = 0

    while attempts < 3:
        try:
            res = requests.request(_method, url=_url, headers=_headers, data=_data, timeout=_timeout)
            return [
                res.status_code,
                "The requested URL was rejected. Please consult with your administrator." in res.text
                or res.status_code == 403
            ]

        except:
            attempts += 1
            time.sleep(0.1 * attempts)
    return [0, False]


def isTableExists(_table_name):
    """
    Check if table _table_name exists in the DB.
    """
    with engine.connect() as connection:
        return engine.dialect.has_table(connection, _table_name)


def dropTableIfExists(_table_name):
    metadata = MetaData()
    connection = engine.connect()

    # Check if table exists before dropping
    if engine.dialect.has_table(connection, _table_name):
        table_to_drop = Table(_table_name, metadata, autoload_with=engine)
        table_to_drop.drop(engine)
        log.debug('Starting New test, table waf_comparison was dropped')

    # Remember to close the connection
    connection.close()
