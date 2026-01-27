import concurrent.futures
import datetime
import socket
import json
import random
from typing import Any, Dict, List
from pathlib import Path
import sys

from tqdm import tqdm
import pandas as pd
from tabulate import tabulate

from config import conn, LEGITIMATE_PATH, MALICIOUS_PATH, DB_TABLE_NAME, MAX_WORKERS, FAST_MODE_SEED, \
    FAST_MODE_SAMPLE_PERCENTAGE
from helper import load_json_file, send_request, drop_table_if_exists, load_wafs_config, print_table
from logger import log


class Wafs:
    """
    Class for handling all WAF related operations, including health checks, sending payloads, and database upload.
    """

    def __init__(self, max_workers: int = MAX_WORKERS, fast_mode: bool = False) -> None:
        """
        Initialize the Wafs class, setting up the WAF data structure and inverse lookup.

        Args:
            max_workers (int): Number of worker threads for sending payloads.
            fast_mode (bool): If True, process only ~15% of requests with constant seed for reproducibility.
        """
        self.wafs = load_wafs_config()
        self.inverse_waf_dict = {v: k for k, v in self.wafs.items()}
        self.max_workers = max_workers
        self.fast_mode = fast_mode

    def check_connection(self) -> None:
        """
        Perform health and functionality checks for all WAFs.

        Raises:
            ConnectionError: If any WAF fails the health or functionality check.
        """
        results = []
        check_failed = False
        log.debug(
            "Initiating WAF health and functionality checks to verify connectivity, confirm prevention mode, and ensure the WAF is capable of blocking malicious requests.")

        for _waf in self.wafs:
            url = self._get_url_by_waf_name(_waf)

            # Health check: send a test GET request and log if it was successful or not.
            res_status_code, _ = send_request(
                'GET',
                url,
                {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"}
            )
            health_ok = res_status_code == 200
            if health_ok:
                log.info(f"Health check passed - WAF: {_waf}")
            else:
                log.error(
                    f"Health check failed - WAF: {_waf} - please ensure the WAF allows the following request: {url}")
                check_failed = True

            # Functional check: send a potentially harmful GET request and check if it gets blocked.
            malicious_payload = url + "/?a=<script>alert(1)</script>"
            res_status_code, is_blocked = send_request('GET', malicious_payload)
            functional_ok = is_blocked
            if functional_ok:
                log.info(f"WAF functionality check passed - WAF: {_waf}")
            else:
                log.error(
                    f"WAF functionality check failed - WAF: {_waf} - please ensure the WAF blocks the following payload: {malicious_payload}")
                check_failed = True
            results.append({
                "Waf Name": _waf,
                "URL": url,
                "Health Check": "✓" if health_ok else "✗",
                "Functional Check": "✓" if functional_ok else "✗"
            })

        title = "WAF Health & Functional Check Summary"
        table = tabulate(results, headers="keys", tablefmt="grid", colalign=("left", "left", "center", "center"))
        print_table(title, table)

        if check_failed:
            log.error(
                "One or more WAFs failed health or functionality checks. Please verify that all WAF URLs are correct, accessible, and operating in prevention mode to block malicious payloads. See the table above for details.")
            sys.exit()
        else:
            log.debug("All tests have been successfully completed.")

    def _sample_data(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Shuffle and sample approximately 15% of the data with a constant seed for reproducibility.

        Args:
            data (List[Dict[str, Any]]): Original list of request objects.

        Returns:
            List[Dict[str, Any]]: Sampled list containing ~15% of the original data, rounded to whole objects.
        """
        # Calculate sample size (rounded to ensure whole objects)
        sample_size = max(1, round(len(data) * FAST_MODE_SAMPLE_PERCENTAGE))

        # Create a copy to avoid modifying the original list
        data_copy = data.copy()

        # Shuffle with constant seed for reproducibility
        random.seed(FAST_MODE_SEED)
        random.shuffle(data_copy)

        # Return the sampled data
        return data_copy[:sample_size]

    def send_payloads(self) -> None:
        """
        Send legitimate & malicious payloads to all WAFs, iterating over all test data and WAF URLs.
        Drops old results before sending new payloads.
        """
        if not self.wafs.values():
            log.error('wafs_config.json is empty.')
            sys.exit()
        # Delete old results before sending new payloads
        drop_table_if_exists(DB_TABLE_NAME)
        log.info("Starting to send legitimate & malicious requests to WAFs...")
        # Send malicious and legitimate payloads to each WAF from datasets files
        for test_name in tqdm(list(MALICIOUS_PATH.rglob("*.json")) + list(LEGITIMATE_PATH.rglob("*.json")),
                              desc="Sending Requests...", position=1, leave=False):
            data = load_json_file(test_name)
            # Apply ~15% requests sampling if fast mode is enabled
            if self.fast_mode:
                data = self._sample_data(data)
            for url in tqdm(self.wafs.values(), position=2, leave=False):
                self._send_payloads(data, url, test_name)
        tqdm.write("")
        log.info("Finished sending legitimate & malicious requests.")

    def _get_url_by_waf_name(self, key: str) -> str:
        """
        Retrieve the WAF URL by its name.

        Args:
            key (str): WAF name.
        Returns:
            str: WAF URL.
        """
        return self.wafs[key]

    def _get_waf_name_by_url(self, key: str) -> str:
        """
        Retrieve the WAF name by its URL.

        Args:
            key (str): WAF URL.
        Returns:
            str: WAF name.
        """
        return self.inverse_waf_dict[key]

    def _send_payloads(self, _data: List[Dict[str, Any]], _url: str, _test_name: Path) -> None:
        """
        Send a set of payloads to a specific WAF using a thread pool. Upload results to the database.

        Args:
            _data (List[Dict[str, Any]]): List of payloads.
            _url (str): WAF URL.
            _test_name (Path): Test name/path object.
        """
        # Use ThreadPoolExecutor for concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as _executor:
            res = list(
                tqdm(
                    _executor.map(
                        lambda payload: send_request(
                            payload['method'],
                            _url + payload['url'],
                            payload['headers'],
                            payload['data']
                        ),
                        _data
                    ),
                    position=3, leave=False, total=len(_data)
                )
            )
        dff = pd.DataFrame(_data)
        dff['machineName'] = socket.gethostname()
        dff['DestinationURL'] = _url
        dff['WAF_Name'] = self._get_waf_name_by_url(_url)
        dff['DateTime'] = datetime.datetime.now()
        dff['TestName'] = _test_name.stem
        dff['DataSetType'] = _test_name.parent.stem
        dff['headers'] = dff['headers'].apply(json.dumps)
        dff[['response_status_code', 'isBlocked']] = res
        # Replacing null bytes with Unicode replacement character in order to save letter in the database
        dff['url'] = dff['url'].str.replace("\x00", "\uFFFD")
        dff['data'] = dff['data'].str.replace("\x00", "\uFFFD")

        # Add TestId
        dff['TestId'] = range(1, len(dff) + 1)

        # Add Category column by mapping from file_category_mapping.json
        mapping_path = Path(__file__).parent / 'assets' / 'file_category_mapping.json'
        with open(mapping_path) as f:
            file_category_mapping = json.load(f)
        dff['Category'] = dff['TestName'].map(file_category_mapping)
        mask = (dff['DataSetType'] == 'Malicious') & (dff['Category'].isnull())
        dff.loc[mask, 'Category'] = dff.loc[mask, 'TestName']

        # Upload the DataFrame to the database
        dff.to_sql(DB_TABLE_NAME, conn, if_exists='append', index=False)
