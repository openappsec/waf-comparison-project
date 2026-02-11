from helper import is_table_exists
from logger import log
from config import RESULTS_PATH, DB_TABLE_NAME
from report.report_generator import create_waf_comparison_pdf_report


def analyzer() -> None:
    """
    Main analysis function to load data and generate PDF comparison report.

    Checks for the existence of the required database table and ensures the output directory exists.
    Generates a PDF report containing detailed WAF comparison results, saved in the results' directory.
    """
    # Check if the database table exists
    if not is_table_exists(DB_TABLE_NAME):
        log.warning(f"Table {DB_TABLE_NAME} doesn't exist in the DB. The analyzer was called before the runner.")
        log.warning("Please make sure to fill the config flags '--waf-name' and '--waf-url' and run the command again.")
        return

    # Ensure output directory exists for saving the report
    RESULTS_PATH.mkdir(exist_ok=True)

    # Analyze WAFs performance results and generate PDF report
    create_waf_comparison_pdf_report()


if __name__ == "__main__":
    analyzer()
