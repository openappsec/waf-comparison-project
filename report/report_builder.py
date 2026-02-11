import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Tuple, List

import pandas as pd

from config import INCLUDE_WAF_BENCHMARKS_2025_2026
from helper import load_wafs_config, load_json_file
from logger import log
from report.graphs import get_scatter_plot_graph, get_bar_chart, get_gauge, \
    get_score_card_data, is_pre_tested_waf_row, format_score, \
    get_polar_bar_chart, get_score_color, get_score_text, \
    POLAR_BAR_CHART_SECURITY_QUALITY_TEXTS, POLAR_BAR_CHART_DETECTION_QUALITY_TEXTS
from report.data_loader import get_blocked_attack_coverage_data, \
    get_allowed_legitimate_coverage_data, get_true_positive_data_samples, \
    get_false_negative_data_samples, \
    get_true_negative_data_samples, get_false_positive_data_samples, get_malicious_counts, \
    get_legitimate_counts


def _add_is_pre_tested_wafs_data(_df: pd.DataFrame) -> pd.DataFrame:
    """
    Extend WAFs results with pre-tested WAFs benchmark results.

    Args:
        _df (pd.DataFrame): DataFrame with current WAF test results.
    Returns:
        pd.DataFrame: Combined current and pre-tested WAFs data, or original if loading fails.
    """
    try:
        waf_results_file = Path(__file__).parent / 'waf_results_2025_2026.json'
        waf_results_2025_2026 = load_json_file(waf_results_file)
        pre_tested_wafs_rows = []
        for waf_name, metrics in waf_results_2025_2026.items():
            pre_tested_wafs_rows.append({
                'WAF Name': waf_name,
                'True Positive Rate': metrics['Security Quality (TPR)'],
                'True Negative Rate': metrics['Detection Quality (TNR)'],
                'Balanced Accuracy': metrics['Balanced Accuracy'],
                'is_pre_tested': True
            })
        pre_tested_wafs_df = pd.DataFrame(pre_tested_wafs_rows)
        # Merge pre-tested WAFs data with current tested WAFs data
        _df = pd.concat([_df, pre_tested_wafs_df], ignore_index=True)
    except Exception as e:
        log.warning(f"Could not add WCP 2025-2026 pre-tested WAFs benchmark results data to graph: {e}")
    return _df


def get_all_waf_request_counts() -> Tuple[dict, dict]:
    """
    Get the total requests count for all WAFs.

    Returns:
        Tuple[dict, dict]: Dicts mapping WAF names to legitimate and malicious request counts.
    """
    legitimate_counts_df = get_legitimate_counts()
    malicious_counts_df = get_malicious_counts()
    legitimate_counts = dict(zip(legitimate_counts_df['WAF Name'], legitimate_counts_df['Legitimate Count']))
    malicious_counts = dict(zip(malicious_counts_df['WAF Name'], malicious_counts_df['Malicious Count']))
    return legitimate_counts, malicious_counts


def _build_single_waf_data(waf_data: Any, data_df: pd.DataFrame, legitimate_counts: dict, malicious_counts: dict) -> \
        Dict[str, Any]:
    """
    Build a complete data record for a single WAF.

    Args:
        waf_data (Any): DataFrame record containing metrics for one WAF.
        data_df (pd.DataFrame): Complete WAFs results DataFrame.
        legitimate_counts (dict): Legitimate request counts per WAF.
        malicious_counts (dict): Malicious request counts per WAF.
    Returns:
        Dict[str, Any]: Single WAF record with nested first_page, second_page, and tables_pages data.
    """
    waf_name = waf_data["WAF Name"]
    waf_data = {
        "waf_name": waf_name,
        "first_page": _get_first_page_data(waf_name, waf_data, data_df, legitimate_counts, malicious_counts),
        "second_page": _get_second_page_data(waf_name, waf_data, data_df),
        "tables_pages": _get_tables_pages_data(waf_name, waf_data),
    }
    return waf_data


def _get_first_page_data(waf_name: str, waf_data: Any, data_df: pd.DataFrame, legitimate_counts: dict,
                         malicious_counts: dict) -> Dict[str, Any]:
    """
    Build data for the first page of the WAF report.

    Args:
        waf_name (str): Name of the WAF.
        waf_data (Any): DataFrame record containing metrics for one WAF.
        data_df (pd.DataFrame): Complete WAFs results DataFrame.
        legitimate_counts (dict): Legitimate request counts per WAF.
        malicious_counts (dict): Malicious request counts per WAF.
    Returns:
        Dict[str, Any]: First page data including test date, WAF URL, dataset hash, and gauge.
    """
    return {
        "test_date": _get_test_date(),
        "waf_url": load_wafs_config().get(waf_name, "N/A"),
        "requests": get_formatted_request_counts_for_waf(waf_data, legitimate_counts, malicious_counts),
        "gauge": get_gauge(left_percentage=waf_data["True Positive Rate"],
                           right_percentage=waf_data["True Negative Rate"]),
        "bar_chart": get_bar_chart(data_df, waf_name),
        "score_card": get_score_card_data(waf_data),
    }


def _get_test_date() -> str:
    """
    Get the current date.

    Returns:
        str: Current date in "DD Month. YYYY" format (e.g., "25 April. 2025")
    """
    month = datetime.now().strftime("%B")
    return datetime.now().strftime(f"%d {month} %Y")


def _get_second_page_data(waf_name: str, waf_data: Any, data_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Build data for the second page of the WAF report.

    Args:
        waf_name (str): Name of the WAF.
        waf_data (Any): DataFrame record containing metrics for one WAF.
        data_df (pd.DataFrame): Complete WAFs results DataFrame.
    Returns:
        Dict[str, Any]: Second page data with polar bar charts and scatter plot.
    """
    return {
        "polar_bar_chart_malicious": _get_malicious_polar_bar_chart(waf_name, waf_data),
        "polar_bar_chart_legitimate": _get_legitimate_polar_bar_chart(waf_name, waf_data),
        "scatter_plot_graph": get_scatter_plot_graph(data_df, waf_name)
    }


def _get_malicious_polar_bar_chart(waf_name: str, waf_data: Any) -> Dict[str, Any]:
    """
    Generate malicious polar bar chart data for a WAF.

    Args:
        waf_name (str): Name of the WAF.
        waf_data (Any): DataFrame record containing metrics for one WAF.
    Returns:
        Dict[str, Any]: Polar bar chart data with TP score.
    """
    data = get_blocked_attack_coverage_data(waf_name)
    tp_score, _, _, _ = _get_scores(waf_data)
    return {
        "chart": get_polar_bar_chart(data),
        "text": get_score_text(tp_score, POLAR_BAR_CHART_SECURITY_QUALITY_TEXTS)
    }


def _get_legitimate_polar_bar_chart(waf_name: str, waf_data: Any) -> Dict[str, Any]:
    """
    Generate legitimate polar bar chart data for a WAF.

    Args:
        waf_name (str): Name of the WAF.
        waf_data (Any): DataFrame record containing metrics for one WAF.
    Returns:
        Dict[str, Any]: Polar bar chart data with TN score.
    """
    data = get_allowed_legitimate_coverage_data(waf_name)
    _, tn_score, _, _ = _get_scores(waf_data)
    return {
        "chart": get_polar_bar_chart(data),
        "text": get_score_text(tn_score, POLAR_BAR_CHART_DETECTION_QUALITY_TEXTS)
    }


def _get_scores(waf_data: Any) -> Tuple[float, float, float, float]:
    """
    Extract scores from WAF data.

    Args:
        waf_data (Any): DataFrame record containing metrics for one WAF.
    Returns:
        Tuple[float, float, float, float]: (TP, TN, FP, FN) scores.
    """
    tp_score = waf_data["True Positive Rate"]
    tn_score = waf_data["True Negative Rate"]
    fp_score = waf_data["False Positive Rate"]
    fn_score = waf_data["False Negative Rate"]
    return tp_score, tn_score, fp_score, fn_score


def _get_tables_pages_data(waf_name: str, waf_data: Any) -> Dict[str, Any]:
    """
    Build data for the tables in the third and fourth pages of the WAF report.

    Args:
        waf_name (str): Name of the WAF.
        waf_data (Any): DataFrame record containing metrics for one WAF.
    Returns:
        Dict[str, Any]: Third & fourth tables pages data with scores, samples, and colors.
    """
    tp_score, tn_score, fp_score, fn_score = _get_scores(waf_data)
    tp_samples, tn_samples, fp_samples, fn_samples = _get_tables_samples(waf_name)
    tp_color, tn_color, fp_color, fn_color = _get_color_by_score(tp_score, tn_score, fp_score, fn_score)

    return {
        "tp": {
            "score": tp_score,
            "samples": tp_samples,
            "color": tp_color
        },
        "tn": {
            "score": tn_score,
            "samples": tn_samples,
            "color": tn_color
        },
        "fp": {
            "score": fp_score,
            "samples": fp_samples,
            "color": fp_color
        },
        "fn": {
            "score": fn_score,
            "samples": fn_samples,
            "color": fn_color
        }
    }


def _get_tables_samples(waf_name: str) -> Tuple[Any, Any, Any, Any]:
    """
    Fetch data samples for TP, TN, FP, FN tables.

    Args:
        waf_name (str): Name of the WAF.
    Returns:
        Tuple[Any, Any, Any, Any]: Data samples for TP, TN, FP, FN tables.
    """
    tp_samples = get_true_positive_data_samples(waf_name)
    fn_samples = get_false_negative_data_samples(waf_name)
    tn_samples = get_true_negative_data_samples(waf_name)
    fp_samples = get_false_positive_data_samples(waf_name)
    return tp_samples, tn_samples, fp_samples, fn_samples


def _get_color_by_score(tp_score: float, tn_score: float, fp_score: float, fn_score: float) -> Tuple[
    str, str, str, str]:
    """
    Determine colors for TP, TN, FP, FN scores.
    For FP and FN, invert the score (100 - score) since lower is better.

    Args:
        tp_score (float): True Positive Rate score.
        tn_score (float): True Negative Rate score.
        fp_score (float): False Positive Rate score.
        fn_score (float): False Negative Rate score.
    Returns:
        Tuple[str, str, str, str]: Colors for TP, TN, FP, FN scores.
    """
    tp_color = get_score_color(tp_score)
    tn_color = get_score_color(tn_score)
    fp_color = get_score_color(100 - fp_score)
    fn_color = get_score_color(100 - fn_score)
    return tp_color, tn_color, fp_color, fn_color


def _get_template_images() -> Dict[str, str]:
    """
    Retrieve all template images needed for the report.

    Returns:
        Dict[str, str]: Dict mapping image names to their content strings.
    """
    return {
        "check_point_logo": _get_image_by_name("check_point.svg"),
    }


def _get_image_by_name(image_name: str) -> str:
    """
    Retrieve the content of an image file from the templates/images directory.

    Args:
        image_name (str): The name of the image file.

    Returns:
        str: Image file content as a string.
    """
    image_path = Path(__file__).parent / "templates" / "images" / image_name
    try:
        with open(image_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        log.error(f"Could not read image {image_name}: {e}")
        sys.exit()


def get_formatted_request_counts_for_waf(waf_data: Any, legitimate_counts: dict, malicious_counts: dict) -> Dict[
    str, str]:
    """
    Get the formatted legitimate and malicious request counts for a WAF.

    Args:
        waf_data (Any): DataFrame record containing metrics for one WAF.
        legitimate_counts (dict): Legitimate request counts per WAF.
        malicious_counts (dict): Malicious request counts per WAF.
    Returns:
        Dict[str, str]: Formatted legitimate and malicious request counts for the WAF.
    """
    waf_name = waf_data["WAF Name"]
    return {
        "legitimate_count": format(int(legitimate_counts[waf_name]), ","),
        "malicious_count": format(int(malicious_counts[waf_name]), ",")
    }


def get_wafs_data_context(data_df: pd.DataFrame) -> Dict[str, List[Dict[str, Any]]]:
    """
    Generate full comparison context data for all WAFs in the dataset, to be used in report generation.

    Args:
        data_df (pd.DataFrame): DataFrame containing metrics for all WAFs.
    Returns:
        Dict[str, List[Dict[str, Any]]]: List of dictionaries, one row per WAF with visualization data.
    """
    wafs_data = []

    # Add pre-tested WAFs benchmark data if configured
    if INCLUDE_WAF_BENCHMARKS_2025_2026:
        data_df = _add_is_pre_tested_wafs_data(data_df)

    # Fetch legitimate counts once for all WAFs
    legitimate_counts, malicious_counts = get_all_waf_request_counts()
    # Process each WAF row
    for _, waf_data in data_df.iterrows():
        for key in ["True Positive Rate", "True Negative Rate", "Balanced Accuracy"]:
            waf_data[key] = format_score(waf_data[key])

        if not is_pre_tested_waf_row(waf_data):
            single_waf_data = _build_single_waf_data(waf_data, data_df, legitimate_counts, malicious_counts)
            wafs_data.append(single_waf_data)
    return {
        "wafs_data": wafs_data,
        "images": _get_template_images()
    }
