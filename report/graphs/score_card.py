from typing import Dict, Any, Tuple
from .constants import COLORS, SCORE_RANGES, BALANCED_ACCURACY_TEXTS, WHAT_IT_MEANS_SECURITY_QUALITY_TEXTS, \
    WHAT_IT_MEANS_DETECTION_QUALITY_TEXTS, WHAT_TO_DO_BALANCED_ACCURACY_TEXTS
from .utils import get_score_color, get_score_text

SCORE_LEGEND_TOTAL_WIDTH = 164
SCORE_LEGEND_GAP = 1.5
SCORE_LEGEND_BAR_HEIGHT = 8
SCORE_LEGEND_SVG_HEIGHT = 14


def _get_scores_texts(
        balanced_accuracy_percentage: float,
        tp_percentage: float,
        tn_percentage: float
) -> Dict[str, Any]:
    """
    Get assessment texts for balanced accuracy, true positive, and true negative rates.
    Received texts are the result and bullet points texts for 'what it means' and 'what to do' sections.

    Args:
        balanced_accuracy_percentage (float): Balanced accuracy percentage (0-100).
        tp_percentage (float): True positive rate percentage (0-100).
        tn_percentage (float): True negative rate percentage (0-100).

    Returns:
        Dict[str, Any]: Dict with main result and bullet points texts.
    """
    balanced_accuracy_text = get_score_text(balanced_accuracy_percentage, BALANCED_ACCURACY_TEXTS)
    what_it_means_text = f"{get_score_text(tp_percentage, WHAT_IT_MEANS_SECURITY_QUALITY_TEXTS)} {get_score_text(tn_percentage, WHAT_IT_MEANS_DETECTION_QUALITY_TEXTS)}"
    what_to_do_text = get_score_text(balanced_accuracy_percentage, WHAT_TO_DO_BALANCED_ACCURACY_TEXTS)

    return {
        "result": balanced_accuracy_text,
        "what_it_means": what_it_means_text,
        "what_to_do": what_to_do_text
    }


def _generate_score_legend_svg(score: float) -> str:
    """
    Generate SVG colored legend bar for score reference with position indicator.

    Args:
        score (float): The score value (0-100) to show the indicator position.

    Returns:
        str: SVG markup string for the legend bar.
    """
    total_width = SCORE_LEGEND_TOTAL_WIDTH
    gap = SCORE_LEGEND_GAP
    bar_height = SCORE_LEGEND_BAR_HEIGHT
    svg_height = SCORE_LEGEND_SVG_HEIGHT

    # Calculate block widths based on score ranges
    bad_range = SCORE_RANGES['poor'] - SCORE_RANGES['bad']  # 61-0 = 61
    poor_range = SCORE_RANGES['normal'] - SCORE_RANGES['poor']  # 71-61 = 10
    normal_range = SCORE_RANGES['good'] - SCORE_RANGES['normal']  # 81-71 = 10
    good_range = SCORE_RANGES['excellent'] - SCORE_RANGES['good']  # 96-81 = 15
    excellent_range = 100 - SCORE_RANGES['excellent']  # 100-96 = 4

    total_range = 100

    # Calculate block widths proportionally (minus gaps)
    available_width = total_width - (gap * 4)  # 4 gaps between 5 blocks
    bad_width = available_width * (bad_range / total_range)
    poor_width = available_width * (poor_range / total_range)
    normal_width = available_width * (normal_range / total_range)
    good_width = available_width * (good_range / total_range)
    excellent_width = available_width * (excellent_range / total_range)

    # Calculate x positions
    bad_x = 0
    poor_x = bad_x + bad_width + gap
    normal_x = poor_x + poor_width + gap
    good_x = normal_x + normal_width + gap
    excellent_x = good_x + good_width + gap

    # Use helper to get block info
    block_start, block_width, block_min, block_max = _get_score_legend_block(
        score,
        bad_x, bad_width,
        poor_x, poor_width,
        normal_x, normal_width,
        good_x, good_width,
        excellent_x, excellent_width
    )

    # Clamp score to block range
    clamped_score = min(max(score, block_min), block_max)
    # Calculate relative position within the block
    if block_max - block_min == 0:
        rel = 0
    else:
        rel = (clamped_score - block_min) / (block_max - block_min)
    pointer_x = block_start + rel * block_width

    bar_y = (svg_height - bar_height) / 2  # Center the bars vertically

    return _build_score_legend_svg(
        total_width, svg_height, bar_height,
        bad_x, bad_width,
        poor_x, poor_width,
        normal_x, normal_width,
        good_x, good_width,
        excellent_x, excellent_width,
        pointer_x, bar_y
    )


def _get_score_legend_block(
        score: float,
        bad_x: float, bad_width: float,
        poor_x: float, poor_width: float,
        normal_x: float, normal_width: float,
        good_x: float, good_width: float,
        excellent_x: float, excellent_width: float
) -> Tuple[float, float, float, float]:
    """
    Determine the block start, width, min, and max for the score pointer in the legend.

    Args:
        score (float): The score value (0-100).
        *_x, *_width (float): X positions and widths for each block.

    Returns:
        Tuple[float, float, float, float]: (block_start, block_width, block_min, block_max)
    """
    if score < SCORE_RANGES['poor']:
        return bad_x, bad_width, SCORE_RANGES['bad'], SCORE_RANGES['poor']
    elif score < SCORE_RANGES['normal']:
        return poor_x, poor_width, SCORE_RANGES['poor'], SCORE_RANGES['normal']
    elif score < SCORE_RANGES['good']:
        return normal_x, normal_width, SCORE_RANGES['normal'], SCORE_RANGES['good']
    elif score < SCORE_RANGES['excellent']:
        return good_x, good_width, SCORE_RANGES['good'], SCORE_RANGES['excellent']
    else:
        return excellent_x, excellent_width, SCORE_RANGES['excellent'], 100


def _build_score_legend_svg(
        total_width: float,
        svg_height: float,
        bar_height: float,
        bad_x: float, bad_width: float,
        poor_x: float, poor_width: float,
        normal_x: float, normal_width: float,
        good_x: float, good_width: float,
        excellent_x: float, excellent_width: float,
        pointer_x: float,
        bar_y: float
) -> str:
    """
    Build the SVG markup for the score legend bar.

    Args:
        All block positions, widths, pointer position, and SVG dimensions.

    Returns:
        str: SVG markup string.
    """
    return f"""
    <svg width="{total_width}" height="{svg_height}" viewBox="0 0 {total_width} {svg_height}" xmlns="http://www.w3.org/2000/svg">
        <!-- Color blocks with proportional gaps -->
        <rect x="{bad_x}" y="{bar_y}" width="{bad_width}" height="{bar_height}" rx="1.5" fill="{COLORS['red']}"/>
        <rect x="{poor_x}" y="{bar_y}" width="{poor_width}" height="{bar_height}" rx="1.5" fill="{COLORS['orange']}"/>
        <rect x="{normal_x}" y="{bar_y}" width="{normal_width}" height="{bar_height}" rx="1.5" fill="{COLORS['yellow']}"/>
        <rect x="{good_x}" y="{bar_y}" width="{good_width}" height="{bar_height}" rx="1.5" fill="{COLORS['light_green']}"/>
        <rect x="{excellent_x}" y="{bar_y}" width="{excellent_width}" height="{bar_height}" rx="1.5" fill="{COLORS['green']}"/>
        
        <!-- Pointer indicator - simple vertical line tick -->
        <line x1="{pointer_x}" y1="1" x2="{pointer_x}" y2="{svg_height - 1}" stroke="#292929" stroke-width="2" stroke-linecap="round"/>
    </svg>
    """


def get_score_card_data(waf_data: Dict[str, float]) -> Dict[str, Any]:
    """
    Generate all the scorecard data, including the SVG colored legend bar,
    with a score marker, and assessment texts.

    Args:
        waf_data (Dict[str, float]): Dict or Series with WAF metrics including:
            - 'Balanced Accuracy' (float)
            - 'True Positive Rate' (float)
            - 'True Negative Rate' (float)

    Returns:
        Dict[str, Any]: All data needed for the scorecard template.
    """
    tp_percentage = waf_data["True Positive Rate"]
    tn_percentage = waf_data["True Negative Rate"]
    balanced_accuracy_percentage = waf_data["Balanced Accuracy"]

    score_color = get_score_color(balanced_accuracy_percentage)
    score_texts = _get_scores_texts(balanced_accuracy_percentage, tp_percentage, tn_percentage)
    color_legend = _generate_score_legend_svg(balanced_accuracy_percentage)

    return {
        'score': balanced_accuracy_percentage,
        'score_color': score_color,
        'score_texts': score_texts,
        'tp_percentage': tp_percentage,
        'tn_percentage': tn_percentage,
        'color_legend': color_legend,
        'tp_text': f"True positive: {tp_percentage}%",
        'tn_text': f"True negative: {tn_percentage}%"
    }
