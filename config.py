from pathlib import Path
from sqlalchemy import create_engine

RESULTS_PATH = Path("results")
DATA_SETS_PATH = RESULTS_PATH / "datasets"
LEGITIMATE_PATH = DATA_SETS_PATH / "Legitimate"
MALICIOUS_PATH = DATA_SETS_PATH / "Malicious"
LOGS_PATH = RESULTS_PATH / "logs"

DB_DIALECT = "duckdb"
DB_PATH = RESULTS_PATH / "db"
DB_FILE_NAME = "waf_comparison.duckdb"
DB_TABLE_NAME = "waf_comparison"

WAFS_CONFIG_FILE_NAME = "wafs_config.json"

PDF_REPORT_FILE_NAME = "waf-comparison-report.pdf"
HTML_REPORT_FILE_NAME = "waf-comparison-report.html"

# Helps for styling & customizing the PDF report
IS_GENERATE_HTML_REPORT = False

conn = create_engine(f"{DB_DIALECT}:///{DB_PATH / DB_FILE_NAME}")

LEGITIMATE_URL_PATH = "https://downloads.openappsec.io/waf-comparison-project/legitimate.zip"
MALICIOUS_URL_PATH = "https://downloads.openappsec.io/waf-comparison-project/malicious.zip"

INCLUDE_WAF_BENCHMARKS_2025_2026 = True

MAX_WORKERS = 4

# Constant seed for reproducible shuffling in fast mode
FAST_MODE_SEED = 42
FAST_MODE_SAMPLE_PERCENTAGE = 0.15
