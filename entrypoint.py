import shutil
import argparse
from pathlib import Path
import sys

from config import RESULTS_PATH, DB_PATH, DB_FILE_NAME, DATA_SETS_PATH, \
    WAFS_CONFIG_FILE_NAME, LOGS_PATH, MAX_WORKERS, FAST_MODE_SAMPLE_PERCENTAGE
from logger import log, init_file_logging
from runner import runner
from analyzer import analyzer

db_file = DB_PATH / DB_FILE_NAME
wafs_config_file = DB_PATH / WAFS_CONFIG_FILE_NAME


def _validate_directories() -> None:
    """
    Create mounted directories if they don't exist.

    Creates the results, database, and datasets directories from config paths.
    """
    Path(RESULTS_PATH).mkdir(exist_ok=True)
    Path(DB_PATH).mkdir(exist_ok=True)
    Path(DATA_SETS_PATH).mkdir(exist_ok=True)


def _parse_arguments() -> argparse.Namespace:
    """
    Parse and return command line arguments.

    Returns:
        argparse.Namespace: Parsed arguments containing:
            - fresh_run: Boolean flag to delete existing results database and WAFs config files, then run fresh analysis
            - waf_name: List of WAF names (optional, can be used multiple times)
            - waf_url: List of WAF URLs (optional, can be used multiple times)
            - max_workers: Number of worker threads for sending payloads
            - fast: Boolean flag to enable fast mode (sampling ~15% of requests)
    """
    parser = argparse.ArgumentParser(
        description="WAF Comparison Project"
    )
    parser.add_argument(
        "--fresh-run",
        action="store_true",
        help="Delete existing results database and WAFs config files, then run fresh analysis"
    )
    parser.add_argument(
        "--waf-name",
        action="append",
        help="WAF name (can be used multiple times)"
    )
    parser.add_argument(
        "--waf-url",
        action="append",
        help="WAF URL (can be used multiple times)"
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=MAX_WORKERS,
        help=f"Number of worker threads for sending payloads (default: {MAX_WORKERS})"
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Enable fast mode: process only ~15%% of requests (sampled with constant seed for reproducibility)"
    )
    return parser.parse_args()


def _init_logging(is_fresh_run: bool) -> None:
    """
    Initialize logging. Clear old logs if fresh run.

    Args:
        is_fresh_run: Whether to clear existing logs before initializing
    """
    if is_fresh_run:
        _clear_logs()
    init_file_logging()


def _clear_logs() -> None:
    """
    Remove all existing log files from logs directory.
    """
    if LOGS_PATH.exists():
        shutil.rmtree(LOGS_PATH)
    LOGS_PATH.mkdir(parents=True, exist_ok=True)


def _execute_workflow(args: argparse.Namespace) -> None:
    """
    Execute the workflow based on run mode and database/config state.

    Args:
        args: Parsed command line arguments
    """
    db_exists = db_file.exists()
    config_exists = wafs_config_file.exists()
    is_fresh_run = args.fresh_run or not (db_exists and config_exists)
    max_workers = args.max_workers
    fast_mode = args.fast

    if is_fresh_run:
        _clean_existing_data(db_file, wafs_config_file)
        wafs_config = _validate_waf_config(args.waf_name, args.waf_url)
        log.info("Running fresh analysis...")
        if fast_mode:
            log.info(
                f"Fast mode initialized: will sample ~{int(FAST_MODE_SAMPLE_PERCENTAGE * 100)}% of requests with a constant seed.")
        runner(wafs_config, max_workers=max_workers, fast_mode=fast_mode)
    else:
        log.info("Using existing database & WAFs config files for analysis.")
        log.warning(
            "Note: Changes to WAF configurations flags '--waf-name', '--waf-url', '--max-workers' and '--fast' will have *NO EFFECT*.")
        log.warning(
            "To apply configuration changes, use '--fresh-run', notice it will *DELETE* the existing results database, WAFs config files and regenerate results.")
        analyzer()


def _clean_existing_data(_db_file: Path, _wafs_config_file: Path) -> None:
    """
    Delete existing database and WAFs config files if they exist.

    Args:
        _db_file: Path to the database file
        _wafs_config_file: Path to the WAF configuration file
    """
    if _db_file.exists():
        log.info(f"Deleting {_db_file} for fresh rerun.")
        _db_file.unlink()

    if _wafs_config_file.exists():
        log.info(f"Deleting {_wafs_config_file} for fresh rerun.")
        _wafs_config_file.unlink()


def _validate_waf_config(names: list[str] | None, urls: list[str] | None) -> dict[str, str] | None:
    """
    Validate WAF configuration arguments and return a config dictionary.

    Args:
        names: List of WAF names from command line arguments
        urls: List of WAF URLs from command line arguments

    Returns:
        dict[str, str] | None: WAF config dictionary mapping names to URLs, or None if no config provided

    Exits:
        The process will exit with an error message if validation fails.
    """
    # Check Number 1: Return if no config provided
    if not names and not urls:
        log.error("Both '--waf-name' and '--waf-url' arguments must be provided.")
        sys.exit()

    # Check Number 2: Early return if no config provided
    if not (names and urls):
        log.error("Both '--waf-name' and '--waf-url' arguments must be provided if either is used.")
        sys.exit()

    # Check Number 3: Check counts match
    if len(names) != len(urls):
        log.error("Number of '--waf-name' and '--waf-url' arguments must match.")
        sys.exit()

    # Check Number 4: Validate non-empty names
    if any(not name or not name.strip() for name in names):
        log.error("Empty values detected in '--waf-name' arguments. Each WAF name must be non-empty.")
        sys.exit()

    # Check Number 5: Validate non-empty and URL format
    for url in urls:
        if not url or not url.strip():
            log.error(
                "Empty values detected in '--waf-url' arguments. Each WAF URL must be non-empty and start with 'http://' or 'https://'.")
            sys.exit()
        if not (url.strip().lower().startswith("http://") or url.strip().lower().startswith("https://")):
            log.error(
                f"Invalid URL format detected in '--waf-url' argument: '{url}'. Each URL must start with 'http://' or 'https://'.")
            sys.exit()

    # Check Number 6: Validate unique names
    if len(names) != len(set(names)):
        log.error("Duplicate WAF names detected in '--waf-name' arguments. Each WAF name must be unique.")
        log.error(
            "Change the WAF names so each is unique. Example: --waf-name 'WAF 1' --waf-url 'http://waf1' --waf-name 'WAF 2' --waf-url 'http://waf2'")
        sys.exit()

    # Check Number 7: Validate unique URLs
    if len(urls) != len(set(urls)):
        log.error("Duplicate WAF URLs detected in '--waf-url' arguments. Each WAF URL must be unique.")
        log.error(
            "Change the WAF URLs so each is unique. Example: --waf-name 'WAF 1' --waf-url 'http://waf1' --waf-name 'WAF 2' --waf-url 'http://waf2'")
        sys.exit()

    # Check Number 8: Build and validate config dictionary
    wafs_config = dict(zip(names, urls))

    return wafs_config


def main() -> None:
    """
    Main entry point for the WAF Comparison Project.
    """
    _validate_directories()
    args = _parse_arguments()
    _init_logging(args.fresh_run)
    _execute_workflow(args)


if __name__ == "__main__":
    main()
