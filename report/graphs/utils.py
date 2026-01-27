import base64
import math
import sys
from typing import Any, Optional, Union, Dict

import plotly.graph_objects as go
import pandas as pd

from logger import log
from .constants import COLORS, SCORE_RANGES


def convert_figure_to_base64(fig: go.Figure, width: int, height: int, scale: int = 1) -> Optional[str]:
    """
    Convert Plotly figure to base64-encoded PNG image for HTML embedding.

    Args:
        fig (go.Figure): Plotly figure object.
        width (int): Width of the image in pixels.
        height (int): Height of the image in pixels.
        scale (int): Scale factor for higher resolution (default=1).

    Returns:
        str: Base64-encoded data URI string.
    """
    try:
        img_bytes = fig.to_image(format="png", width=width, height=height, scale=scale)
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        base64_image = f"data:image/png;base64,{img_base64}"
        return base64_image
    except Exception as e:
        log.error(f"Could not generate base64 image from figure: {e}")
        sys.exit()


def format_score(value: float) -> Union[int, float]:
    """
    Format score to 1 decimal place (truncate), convert whole numbers to int.

    Args:
        value (float): Numeric value to format.

    Returns:
        int or float: Formatted value (e.g., 87.253 -> 87.2, 99.0 -> 99).
    """
    floored = math.floor(value * 10) / 10
    return int(floored) if floored == int(floored) else floored


def is_pre_tested_waf_row(row: Union[pd.Series, Dict[str, Any]]) -> bool:
    """
    Check if a DataFrame row represents pre-tested WAF data.

    Args:
        row (pd.Series or dict): WAF data DataFrame row.

    Returns:
        bool: True if the row is pre-tested WAF data, False otherwise.
    """
    return "is_pre_tested" in row and pd.notna(row["is_pre_tested"]) and row["is_pre_tested"]


def get_score_color(score: float) -> str:
    """
    Determine the color based on the score value.

    Args:
        score (float): Numeric score value (0-100).

    Returns:
        str: Hex color code.
    """
    if score >= SCORE_RANGES['excellent']:
        return COLORS['green']
    elif score >= SCORE_RANGES['good']:
        return COLORS['light_green']
    elif score >= SCORE_RANGES['normal']:
        return COLORS['yellow']
    elif score >= SCORE_RANGES['poor']:
        return COLORS['orange']
    else:
        return COLORS['red']


def get_score_text(score: float, items: Dict[str, str]) -> str:
    """
    Get the corresponding text for a given score.

    Args:
        score (float): Numeric score value (0-100).
        items (dict): Mapping of category names to text.

    Returns:
        str: text corresponding to the score category (e.g., texts['excellent'] = 'Excellent WAF').
    """
    if score >= SCORE_RANGES['excellent']:
        return items['excellent']
    elif score >= SCORE_RANGES['good']:
        return items['good']
    elif score >= SCORE_RANGES['normal']:
        return items['normal']
    elif score >= SCORE_RANGES['poor']:
        return items['poor']
    else:
        return items['bad']


def get_timestamped_filename(base_name: str, timestamp: str) -> str:
    """
    Generate a filename with a timestamp appended before the extension.
    Args:
        base_name (str): The base filename (e.g., 'waf-comparison-report.pdf').
        timestamp (str): The timestamp string (e.g., '20251126_153045').
    Returns:
        str: Filename with timestamp (e.g., 'waf-comparison-report_20251126_153045.pdf').
    """
    name, ext = base_name.rsplit('.', 1)
    return f"{name}_{timestamp}.{ext}"
