from typing import Any, List, Dict
import sys

import pandas as pd
from sqlalchemy import text

from config import conn, DB_TABLE_NAME
from logger import log

HEADER_LENGTH_LIMIT = 800
SAMPLES_MAX_RECORDS = 7


def load_data() -> pd.DataFrame:
    """
    Load and aggregate WAF comparison data from the database.

    Returns:
        pd.DataFrame: DataFrame with WAF metrics and counts, columns renamed for reporting.
    """
    query = text(f""" 
            WITH TNR AS (SELECT "WAF_Name",
                            SUM(CASE WHEN "isBlocked" = 0 THEN 1.0 ELSE 0.0 END) / COUNT(*) * 100 AS true_negative_rate
                     FROM {DB_TABLE_NAME}
                     WHERE response_status_code != 0 AND "DataSetType" = 'Legitimate'
            GROUP BY "WAF_Name"
                ),
                TPR AS (
            SELECT "WAF_Name", SUM (CASE WHEN "isBlocked" = 1 THEN 1.0 ELSE 0.0 END) / COUNT (*) * 100 AS true_positive_rate
            FROM {DB_TABLE_NAME}
            WHERE response_status_code != 0 AND "DataSetType" = 'Malicious'
            GROUP BY "WAF_Name"
                )
            SELECT TPR."WAF_Name",
                   1337 AS reference_id,
                   ROUND(100 - TNR.true_negative_rate, 1)                          AS false_positive_rate,
                   ROUND(100 - TPR.true_positive_rate, 1)                          AS false_negative_rate,
                   ROUND(TPR.true_positive_rate, 1)                                AS true_positive_rate,
                   ROUND(TNR.true_negative_rate, 1)                                AS true_negative_rate,
                   ROUND((TPR.true_positive_rate + TNR.true_negative_rate) / 2, 1) AS balanced_accuracy
            FROM TPR
            JOIN TNR ON TPR."WAF_Name" = TNR."WAF_Name"
            ORDER BY balanced_accuracy DESC;
        """)
    df = pd.read_sql_query(query, conn)
    _validate_df(df)
    return df.rename({
        "WAF_Name": "WAF Name",
        "false_positive_rate": "False Positive Rate",
        "false_negative_rate": "False Negative Rate",
        "true_positive_rate": "True Positive Rate",
        "true_negative_rate": "True Negative Rate",
        "balanced_accuracy": "Balanced Accuracy",
    }, axis=1).copy()


def get_legitimate_counts() -> pd.DataFrame:
    """
    Get the count of legitimate records for all WAFs.

    Returns:
        pd.DataFrame: DataFrame with columns 'WAF Name' and 'Legitimate Count' for each WAF.
    """
    query = text(f'''
        SELECT "WAF_Name", COUNT(*) AS legitimate_count
        FROM {DB_TABLE_NAME}
        WHERE "DataSetType" = 'Legitimate'
        GROUP BY "WAF_Name";
    ''')
    df = pd.read_sql_query(query, conn)
    _validate_df(df)
    return df.rename({
        "WAF_Name": "WAF Name",
        "legitimate_count": "Legitimate Count"
    }, axis=1).copy()


def get_malicious_counts() -> pd.DataFrame:
    """
    Get the count of malicious records for all WAFs.

    Returns:
        pd.DataFrame: DataFrame with columns 'WAF Name' and 'Malicious Count' for each WAF.
    """
    query = text(f"""
        SELECT "WAF_Name", COUNT(*) AS malicious_count
        FROM {DB_TABLE_NAME}
        WHERE "DataSetType" = 'Malicious'
        GROUP BY "WAF_Name";
    """)
    df = pd.read_sql_query(query, conn)
    _validate_df(df)
    return df.rename({
        "WAF_Name": "WAF Name",
        "malicious_count": "Malicious Count"
    }, axis=1).copy()


def get_blocked_attack_coverage_data(waf_name: str) -> pd.DataFrame:
    """
    Get blocked attack coverage data for a WAF.

    Args:
        waf_name (str): Name of the WAF.
    Returns:
        pd.DataFrame: DataFrame with attack categories and blocked coverage scores.
    """
    query = text(f"""
        SELECT "Category",
               SUM(CASE WHEN "isBlocked" = 1 THEN 1 ELSE 0 END)::numeric / COUNT(*) * 100 AS true_positive_rate
        FROM {DB_TABLE_NAME}
        WHERE "DataSetType" = 'Malicious'
          AND "WAF_Name" = :waf_name
        GROUP BY "Category" ORDER BY "Category" ASC;
    """)
    df = pd.read_sql_query(query, conn, params={"waf_name": waf_name})
    _validate_df(df)
    return df.rename({
        "Category": "Attack Category",
        "true_positive_rate": "Blocked Malicious Coverage",
    }, axis=1).copy()


def get_allowed_legitimate_coverage_data(waf_name: str) -> pd.DataFrame:
    """
    Get allowed legitimate coverage data for a WAF.

    Args:
        waf_name (str): Name of the WAF.
    Returns:
        pd.DataFrame: DataFrame with legitimate categories and allowed coverage scores.
    """
    query = text(f"""
        SELECT "Category",
               SUM(CASE WHEN "isBlocked" = 0 THEN 1 ELSE 0 END)::numeric / COUNT(*) * 100 AS true_negative_rate
        FROM {DB_TABLE_NAME}
        WHERE "DataSetType" = 'Legitimate' 
          AND "WAF_Name"   = :waf_name
        GROUP BY "Category" ORDER BY "Category" ASC;
    """)
    df = pd.read_sql_query(query, conn, params={"waf_name": waf_name})
    _validate_df(df)
    return df.rename({
        "Category": "Legitimate Category",
        "true_negative_rate": "Allowed Legitimate Coverage",
    }, axis=1).copy()


def get_true_positive_data_samples(waf_name: str) -> List[Dict[str, Any]]:
    """
    Get true positive (blocked malicious) data samples for a WAF.

    Args:
        waf_name (str): Name of the WAF.
    Returns:
        List[Dict[str, Any]]: List of TP sample records.
    """
    return _fetch_malicious_samples(waf_name, is_blocked=True)


def get_false_negative_data_samples(waf_name: str) -> List[Dict[str, Any]]:
    """
    Get false negative (missed malicious) data samples for a WAF.

    Args:
        waf_name (str): Name of the WAF.
    Returns:
        List[Dict[str, Any]]: List of FN sample records.
    """
    return _fetch_malicious_samples(waf_name, is_blocked=False)


def get_false_positive_data_samples(waf_name: str) -> List[Dict[str, Any]]:
    """
    Get false positive (incorrectly blocked legitimate) data samples for a WAF.

    Args:
        waf_name (str): Name of the WAF.
    Returns:
        List[Dict[str, Any]]: List of FP sample records.
    """
    return _fetch_legitimate_samples(waf_name, is_blocked=True)


def get_true_negative_data_samples(waf_name: str) -> List[Dict[str, Any]]:
    """
    Get true negative (allowed legitimate) data samples for a WAF.

    Args:
        waf_name (str): Name of the WAF.
    Returns:
        List[Dict[str, Any]]: List of TN sample records.
    """
    return _fetch_legitimate_samples(waf_name, is_blocked=False)


def _fetch_malicious_samples(waf_name: str, *, is_blocked: bool) -> List[Dict[str, Any]]:
    """
    Fetch sample malicious requests for a WAF, filtered by block status.

    Args:
        waf_name (str): Name of the WAF.
        is_blocked (bool): Whether to fetch blocked (TP) or missed (FN) malicious samples.
    Returns:
        List[Dict[str, Any]]: List of sample records as dictionaries.
    """
    query = text(f""" 
         WITH ranked AS (
            SELECT "TestName", "url", "TestId",
                ROW_NUMBER() OVER (
                    PARTITION BY "url"
                    ORDER BY length(url)
                ) AS url_rank,
        
                ROW_NUMBER() OVER (
                    PARTITION BY "TestName"
                    ORDER BY length(url)
                ) AS testname_rank
        
            FROM {DB_TABLE_NAME}
            WHERE "DataSetType" = 'Malicious'
              AND "WAF_Name"    = :waf_name
              AND "isBlocked"   = :is_blocked
              AND method        = 'GET'
        )
        SELECT "TestName", "url", "TestId",
        FROM ranked
        WHERE url_rank = 1
          AND testname_rank = 1
        ORDER BY "TestName"
        LIMIT {SAMPLES_MAX_RECORDS};

    """)
    df = pd.read_sql_query(query, conn, params={"waf_name": waf_name, "is_blocked": int(is_blocked)})
    _validate_df(df)
    return df.rename({
        "TestName": "test_name", "TestId": "test_id"
    }, axis=1).copy().to_dict('records')


def _fetch_legitimate_samples(waf_name: str, *, is_blocked: bool) -> List[Dict[str, Any]]:
    """
    Fetch sample legitimate requests for a WAF, filtered by block status.

    Args:
        waf_name (str): Name of the WAF.
        is_blocked (bool): Whether to fetch incorrectly blocked (FP) or allowed (TN) legitimate samples.
    Returns:
        List[Dict[str, Any]]: List of sample records as dictionaries.
    """
    query = text(f"""
        WITH ranked AS (
            SELECT "TestName", "url", "TestId",
                ROW_NUMBER() OVER (
                    PARTITION BY "url"
                    ORDER BY length(url)
                ) AS url_rank,
                ROW_NUMBER() OVER (
                    PARTITION BY "TestName"
                    ORDER BY length(url)
                ) AS testname_rank
            FROM {DB_TABLE_NAME}
            WHERE "DataSetType" = 'Legitimate'
              AND "WAF_Name"    = :waf_name
              AND "isBlocked"   = :is_blocked
              AND method = 'GET'
              AND length(url) > 5
              AND length(headers) < :header_limit
        )
        SELECT "TestName", "url", "TestId"
        FROM ranked
        WHERE url_rank = 1  
          AND testname_rank = 1
        ORDER BY "TestName"
        LIMIT {SAMPLES_MAX_RECORDS};
    """)

    def run_with(header_limit: int) -> pd.DataFrame:
        df = pd.read_sql_query(
            query, conn,
            params={"waf_name": waf_name, "is_blocked": int(is_blocked),
                    "header_limit": header_limit}
        )
        _validate_df(df)
        return df

    df = run_with(HEADER_LENGTH_LIMIT)
    if df.shape[0] < SAMPLES_MAX_RECORDS:
        df = run_with(HEADER_LENGTH_LIMIT * 2)
    return (
        df.rename(columns={"TestName": "test_name", "TestId": "test_id"})
        .copy()
        .to_dict("records")
    )


def _validate_df(df: Any) -> None:
    """
    Validate that the DataFrame is not None. If None, log error and exit.

    Args:
        df (Any): DataFrame to validate.
    """
    if df is None:
        log.error("No data returned from results DB.")
        sys.exit()
