import sys
from typing import Any, Dict
from pathlib import Path
import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape
from tabulate import tabulate
from weasyprint.text.fonts import FontConfiguration
from weasyprint import HTML, CSS

from config import (INCLUDE_WAF_BENCHMARKS_2025_2026, RESULTS_PATH, PDF_REPORT_FILE_NAME, \
                    HTML_REPORT_FILE_NAME, IS_GENERATE_HTML_REPORT)
from helper import print_table
from report.graphs.utils import get_timestamped_filename
from report.report_builder import get_wafs_data_context
from report.data_loader import load_data
from logger import log

BASE_DIR = Path(__file__).resolve().parent

env = Environment(
    loader=FileSystemLoader(BASE_DIR / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

REPORT_TIMESTAMP = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M')
PDF_OUTPUT_FILE_PATH = RESULTS_PATH / get_timestamped_filename(PDF_REPORT_FILE_NAME, REPORT_TIMESTAMP)
HTML_OUTPUT_FILE_PATH = RESULTS_PATH / get_timestamped_filename(HTML_REPORT_FILE_NAME, REPORT_TIMESTAMP)


def _render_html_report(context: Dict[str, Any]) -> str:
    """
    Render the HTML report using Jinja2 template engine.
    Takes the context data and inserts it into the HTML template,
    to generate the final HTML string.
    Args:
        context (Dict[str, Any]): Dictionary containing all template variables.
    Returns:
        str: Fully rendered HTML report as a string.
    """
    log.info("Rendering comparison results data with styled template...")
    # Load the report template
    template = env.get_template("report.html")
    # Render template with context data
    html_str = template.render(**context)

    return html_str


def _save_html_report(html_str: str) -> None:
    """
    Save the rendered HTML report to a file in the results' directory.

    Args:
        html_str (str): Complete HTML content as string.
    """
    # Embed CSS styles directly into the HTML for standalone file
    log.info(f'Generating HTML report file...')
    try:
        css = (BASE_DIR / "templates" / "styles.css").read_text(encoding="utf-8")
        html_str = html_str.replace('</head>', f'<style>{css}</style></head>')
        with open(HTML_OUTPUT_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write(html_str)
    except Exception as e:
        log.error(f"Failed to save HTML report file: {e}")
        sys.exit()


def _save_pdf_report(html_str: str) -> None:
    """
    Convert HTML report string to PDF format and save to file.

    Uses WeasyPrint library to render HTML as PDF, preserving all styling and embedded images.

    Args:
        html_str (str): Complete HTML content to convert into a PDF file.
    Returns:
        None
    """
    log.info(f'Generating PDF report file...')
    font_config = FontConfiguration()
    css_file_path = (BASE_DIR / "templates" / "styles.css")
    css = CSS(filename=css_file_path, font_config=font_config)
    html = HTML(string=html_str)
    html.write_pdf(PDF_OUTPUT_FILE_PATH, stylesheets=[css], font_config=font_config)


def _print_metric(data_df: Any, metric: str, is_ascending: bool) -> None:
    """
    Print a sorted metric from the WAF comparison DataFrame as a table, matching bar chart order.
    Args:
        data_df (Any): DataFrame containing WAF comparison data.
        metric (str): The metric column to sort and print.
        is_ascending (bool): Sort order for the metric.
    """
    # Match bar_chart: sort by metric, then by index, same metric values, higher original index comes first
    _df_sorted = data_df.reset_index(drop=False).sort_values([metric, 'index'], ascending=[is_ascending, False]).copy()
    _df_sorted['Position'] = range(1, len(_df_sorted) + 1)

    title = f"{metric} ({'Ascending' if is_ascending else 'Descending'})"
    results = _df_sorted[['Position', 'WAF Name', metric]].to_dict(orient='records')
    table = tabulate(results, headers="keys", tablefmt="grid", colalign=("left", "left", "center"))

    print_table(title, table)


def _print_waf_results(data_df: Any) -> None:
    """
    Print WAF comparison results to the console.

    Args:
        data_df (Any): DataFrame containing WAF comparison data.
    """
    log.info("Printing score tables:")
    metrics_config = [
        ("False Positive Rate", False),
        ("False Negative Rate", False),
        ("True Positive Rate", True),
        ("True Negative Rate", True),
        ("Balanced Accuracy", True)
    ]
    for metric, is_ascending in metrics_config:
        _print_metric(data_df, metric, is_ascending)
        print()
    log.info("WAF comparison results printed to console.")


def create_waf_comparison_pdf_report() -> None:
    """
    Generate a WAF comparison report as PDF (and optionally HTML), using test results from the database.
    Validates data, prepares context, renders the report, converts it to styled PDF and prints the results.
    """
    log.info(
        f"Analyzing WCP Test Results{' - with pre-tested WCP 2025-2026 benchmark results' if INCLUDE_WAF_BENCHMARKS_2025_2026 else ''}...")
    try:
        # Fetch the WAFs performance data
        data_df = load_data()

        # Validate performance data
        if data_df is None or len(data_df) == 0:
            log.error("Failed generating report: No data available.")
            sys.exit()

        # prepare all data needed for the report
        context = get_wafs_data_context(data_df)

        # insert all context data into the template, render HTML from Jinja2 template
        html_str = _render_html_report(context)

        # generate and save HTML report
        _save_html_report(html_str) if IS_GENERATE_HTML_REPORT else None

        # generate and save PDF report
        _save_pdf_report(html_str)

        # print results to console
        _print_waf_results(data_df)

        log.info("Done analyzing WAFs performance results.")
        log.info(f"HTML report saved to: './{HTML_OUTPUT_FILE_PATH}'.") if IS_GENERATE_HTML_REPORT else None
        log.info(f"PDF report saved to: './{PDF_OUTPUT_FILE_PATH}'.")

    except Exception as e:
        log.error(f"Error occurred while generating report: {e}")
        sys.exit()
