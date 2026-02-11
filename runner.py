import json
from typing import Dict

import pandas as pd

from wafs import Wafs
from analyzer import analyzer
from config import conn, DB_PATH, WAFS_CONFIG_FILE_NAME, MAX_WORKERS
from helper import prepare_data
from logger import log


def _save_wafs_config(config: Dict[str, str]) -> None:
    """
    Save the WAFs configuration to a JSON file.

    Args:
        config (Dict[str, str]): Dictionary containing WAF names and their corresponding URLs.
    """
    DB_PATH.mkdir(exist_ok=True)
    with open(DB_PATH / WAFS_CONFIG_FILE_NAME, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=4)


def check_engine_connection() -> None:
    """
    Check if a successful connection to the database engine can be established.

    Raises:
        ConnectionError: If the database connection fails.
    """
    try:
        _ = pd.read_sql_query("SELECT 1", conn)
        log.info("Database Connected Successfully")
    except Exception as e:
        raise ConnectionError(f"Database Connection Failed: {e}")


def runner(wafs_config: Dict[str, str], max_workers: int = MAX_WORKERS, fast_mode: bool = False) -> None:
    """
    Main function to execute the WAF testing process.

    Args:
        wafs_config (Dict[str, str]): Dictionary containing WAF names and their corresponding URLs.
        max_workers (int): Number of worker threads for sending payloads.
        fast_mode (bool): If True, process only ~15% of requests with constant seed for reproducibility.
    """
    _save_wafs_config(wafs_config)
    wafs = Wafs(max_workers=max_workers, fast_mode=fast_mode)
    wafs.check_connection()
    check_engine_connection()
    prepare_data()
    wafs.send_payloads()
    analyzer()


if __name__ == '__main__':
    DEFAULT_WAFS_CONFIG = {}  # Change to WAFs config dict: {'First WAF': 'http://first-waf.com', ...}
    runner(DEFAULT_WAFS_CONFIG)
