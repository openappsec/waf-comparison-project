import plotly.graph_objects as go
from typing import Dict, Any, List, Tuple

import pandas as pd

from .constants import COLORS, YOUR_RESULT_TEXT
from .utils import convert_figure_to_base64, is_pre_tested_waf_row, get_score_color, format_score
from helper import load_wafs_config
from logger import log

TEXT_COLOR = '#5D6B82'
TEXT_SIZE = 20
BALANCED_ACCURACY_METRIC = 'Balanced Accuracy'
WAF_NAME_COL = 'WAF Name'
BAR_CORNER_RADIUS = 2
BAR_LINE_WIDTH = 0
REFERENCE_LINE_COLOR = "rgba(46,92,109,0.2)"
HIGHLIGHTED_TESTED_WAF_COLOR = "rgba(192, 222, 255, 0.95)"
OTHER_TESTED_WAF_COLOR = "rgba(232, 237, 245, 0.7)"
REFERENCE_LINE_WIDTH = 2
REFERENCE_LINE_ANNOTATION = "90%"
REFERENCE_LINE_ANNOTATION_YSHIFT = -0.5
HIGHLIGHT_Y_OFFSET = 0.48
HIGHLIGHT_RADIUS_X_PAPER = 0.008
HIGHLIGHT_RADIUS_Y_CAT = 0.15
HIGHLIGHT_PAPER_BOUND_START = -0.69
HIGHLIGHT_PAPER_BOUND_END = 1.01
ELLIPSIS_TEXT = "..."
MAX_WAF_NAME_LENGTH = 56  # Adjusted to the longest WAF name in 'waf_results_2025_2026.json'
MAX_HIGHLIGHTED_WAF_NAME_LENGTH = MAX_WAF_NAME_LENGTH - len(
    YOUR_RESULT_TEXT) - 4  # Adjusted to the longest WAF name in 'waf_results_2025_2026.json' minus the "Your result" length minus 4 for bold tags


def _create_bar_chart(_df: pd.DataFrame, current_waf_name: str) -> go.Figure:
    """
    Create a styled bar chart comparing tested WAFs and pre-tested WAFs results.

    Args:
        _df (pd.DataFrame): DataFrame with WAF comparison data.
        current_waf_name (str): Name of the current WAF to highlight.

    Returns:
        go.Figure: Plotly Figure object representing the bar chart.
    """
    sorted_df = _sort_by_metric_and_index(_df, BALANCED_ACCURACY_METRIC)
    bars = _create_bars(sorted_df)
    fig = go.Figure(bars)
    _add_legend_traces(fig, sorted_df, current_waf_name)
    _apply_layout(fig, sorted_df, current_waf_name)
    _add_tested_wafs_highlight(fig, sorted_df, current_waf_name)
    _add_current_waf_highlight(fig, sorted_df, current_waf_name)
    _add_reference_line(fig)
    return fig


def _sort_by_metric_and_index(_df: pd.DataFrame, metric: str) -> pd.DataFrame:
    """
    Sorts the DataFrame by the given metric (ascending) and index (descending).

    Args:
        _df (pd.DataFrame): DataFrame containing WAF comparison data.
        metric (str): Metric column name to sort by.

    Returns:
        pd.DataFrame: Sorted DataFrame.
    """
    return _df.reset_index(drop=False).sort_values([metric, 'index'], ascending=[True, False])


def _create_bars(_df: pd.DataFrame) -> List[go.Bar]:
    """
    Create Plotly bar objects for each WAF in the DataFrame.

    Args:
        _df (pd.DataFrame): DataFrame containing WAF comparison data.

    Returns:
        List[go.Bar]: List of Plotly Bar objects for the chart.
    """
    bars = []
    for idx, waf_data in _df.iterrows():
        balanced_accuracy_score = waf_data[BALANCED_ACCURACY_METRIC]
        waf_name = waf_data[WAF_NAME_COL]
        bar_color = get_score_color(balanced_accuracy_score)

        # Check if pre-tested WAF name exceeds max length
        if is_pre_tested_waf_row(waf_data) and len(waf_name) > MAX_WAF_NAME_LENGTH:
            log.warning(
                f"Pre-tested WAF name '{waf_name}' exceeds maximum length of {MAX_WAF_NAME_LENGTH} characters (length: {len(waf_name)}), it can affect the background highlight display.")

        # Create unique internal identifier to avoid Y-axis conflicts
        unique_y_identifier = f"{waf_name}___{idx}"

        # Format text display - truncate to 1 decimal place
        formatted_score = format_score(balanced_accuracy_score)
        text = f"{formatted_score}%"

        bars.append(go.Bar(
            x=[balanced_accuracy_score],
            y=[unique_y_identifier],
            orientation='h',
            marker=dict(
                color=bar_color,
                line=dict(width=BAR_LINE_WIDTH),
                cornerradius=BAR_CORNER_RADIUS
            ),
            text=text,
            textposition='outside',
            textfont=dict(size=TEXT_SIZE, color=TEXT_COLOR),
            showlegend=False,
            offsetgroup=0,
            base=0.5,
            customdata=[waf_name]
        ))
    return bars


def _add_legend_traces(fig: go.Figure, _df: pd.DataFrame, current_waf_name: str) -> None:
    """
    Add legend traces to the figure to show color-coded score ranges and tested WAFs.

    Args:
        fig (go.Figure): Plotly Figure object to add the legend traces to.
        _df (pd.DataFrame): DataFrame containing WAF comparison data.
        current_waf_name (str): Name of the current WAF to highlight.
    """
    _add_color_range_legend(fig)
    _add_square_legends(fig, _df, current_waf_name)


def _add_color_range_legend(fig: go.Figure) -> None:
    """
    Add color range legend items to the figure.

    Args:
        fig (go.Figure): Plotly Figure object to add the legend items to.
    """
    legend_items = [
        {'label': 'Excellent: 95-100', 'color': COLORS['green']},
        {'label': 'Good: 90-95', 'color': COLORS['light_green']},
        {'label': 'Normal: 80-90', 'color': COLORS['yellow']},
        {'label': 'Poor: 60-80', 'color': COLORS['orange']},
        {'label': 'Bad: 0-60', 'color': COLORS['red']},
    ]
    for item in legend_items:
        fig.add_trace(go.Scatter(
            x=[None],
            y=[None],
            mode='markers',
            marker=dict(size=10, color=item['color'], symbol='circle'),
            name=item['label'],
            showlegend=True,
            textfont=dict(size=TEXT_SIZE + 2, color=TEXT_COLOR)
        ))

    # Add a gap/separator between the two legend groups
    fig.add_trace(go.Scatter(
        x=[None],
        y=[None],
        mode='markers',
        marker=dict(size=0, color='rgba(0,0,0,0)'),
        name=' ',
        showlegend=True,
        hoverinfo='skip'
    ))


def _add_square_legends(fig: go.Figure, _df: pd.DataFrame, current_waf_name: str) -> None:
    """
    Add square legend items for highlighted and other tested WAFs.

    Args:
        fig (go.Figure): Plotly Figure object to add the legend items to.
        _df (pd.DataFrame): DataFrame containing WAF comparison data.
        current_waf_name (str): Name of the current WAF to highlight.
    """
    tested_waf_names = list(load_wafs_config().keys())
    waf_names_in_df = set(_df[WAF_NAME_COL].tolist())

    # Determine if there are other tested WAFs (besides the current one) and that are present in the DataFrame
    other_tested_wafs = [waf for waf in tested_waf_names if waf != current_waf_name and waf in waf_names_in_df]

    # Always add the highlighted legend, only add 'other tested' if any exist in the DataFrame
    fig.add_trace(go.Scatter(
        x=[None],
        y=[None],
        mode='markers',
        marker=dict(
            size=12,
            color=HIGHLIGHTED_TESTED_WAF_COLOR,
            symbol='square-dot',
            line=dict(width=0)
        ),
        name='Highlighted tested WAF',
        showlegend=True,
        textfont=dict(size=TEXT_SIZE + 2, color=TEXT_COLOR)
    ))
    if other_tested_wafs:
        fig.add_trace(go.Scatter(
            x=[None],
            y=[None],
            mode='markers',
            marker=dict(
                size=12,
                color=OTHER_TESTED_WAF_COLOR,
                symbol='square-dot',
                line=dict(width=0)
            ),
            name='Other tested WAFs',
            showlegend=True,
            textfont=dict(size=TEXT_SIZE + 2, color=TEXT_COLOR)
        ))


def _apply_layout(fig: go.Figure, _df: pd.DataFrame, current_waf_name: str) -> None:
    """
    Apply layout properties to the given Plotly Figure.

    Args:
        fig (go.Figure): The Plotly Figure to update.
        _df (pd.DataFrame): DataFrame containing WAF comparison data.
        current_waf_name (str): Name of the current WAF to highlight.
    """
    layout_props = _get_layout_props()

    # Get Y-axis tick mapping
    tickvals, ticktext = _get_yaxis_tick_mapping(_df, current_waf_name)

    # Update yaxis with custom tick labels
    layout_props['yaxis']['tickvals'] = tickvals
    layout_props['yaxis']['ticktext'] = ticktext

    fig.update_layout(**layout_props)


def _get_layout_props() -> Dict[str, Any]:
    """
    Get layout properties for the bar chart.

    Returns:
        Dict[str, Any]: Dictionary of layout properties for Plotly Figure.
    """
    return dict(
        font=dict(size=TEXT_SIZE, color=TEXT_COLOR, family='Inter, sans-serif'),
        xaxis=dict(
            title=None,
            gridcolor='rgba(210,216,227,0.5)',
            showgrid=True,
            zeroline=False,
            range=[0, 108],
            ticksuffix='%',
            tickfont=dict(size=TEXT_SIZE, color=TEXT_COLOR),
        ),
        yaxis=dict(
            title=None,
            gridcolor='rgba(0,0,0,0)',
            showgrid=False,
            tickfont=dict(size=TEXT_SIZE, color=TEXT_COLOR)
        ),
        plot_bgcolor='rgba(255,255,255,1)',
        paper_bgcolor='rgba(255,255,255,1)',
        margin=dict(t=20, b=40, l=350, r=120),
        bargap=0.55,
        width=1800,
        height=700,
        legend=dict(
            x=1.02,
            y=0.5,
            xanchor='left',
            yanchor='middle',
            bgcolor='rgba(255,255,255,0)',
            bordercolor='rgba(0,0,0,0)',
            borderwidth=0,
            font=dict(size=TEXT_SIZE, color=TEXT_COLOR)
        ),
    )


def _get_yaxis_tick_mapping(_df: pd.DataFrame, current_waf_name: str) -> Tuple[List[str], List[str]]:
    """
    Create mapping of unique Y-axis identifiers to display names.

    Args:
        _df (pd.DataFrame): DataFrame containing WAF comparison data.
        current_waf_name (str): Name of the current WAF to highlight.

    Returns:
        Tuple[List[str], List[str]]: A tuple containing:
            - tickvals: List of unique Y-axis identifiers
            - ticktext: List of formatted display labels for each WAF
    """
    tickvals = []
    ticktext = []
    for idx, waf_data in _df.sort_values(BALANCED_ACCURACY_METRIC, ascending=True).iterrows():
        waf_name = waf_data[WAF_NAME_COL]
        unique_y_identifier = f"{waf_name}___{idx}"
        is_current_waf = waf_name == current_waf_name and not is_pre_tested_waf_row(waf_data)

        waf_display_name = _get_waf_display_name(is_current_waf, waf_name)

        tickvals.append(unique_y_identifier)
        ticktext.append(waf_display_name)

    return tickvals, ticktext


def _get_waf_display_name(is_current_waf: bool, waf_name: str) -> str:
    """
    Format the WAF display name, applying highlighting when it is the current WAF
    and truncating with an ellipsis when it exceeds the configured maximum length.

    Args:
        is_current_waf (bool): Whether the WAF is the current one.
        waf_name (str): The original WAF name.

    Returns:
        str: Formatted WAF display name.
    """
    waf_display_name = waf_name

    if is_current_waf:
        if len(waf_name) > MAX_HIGHLIGHTED_WAF_NAME_LENGTH:
            waf_name = waf_name[:MAX_HIGHLIGHTED_WAF_NAME_LENGTH - len(ELLIPSIS_TEXT)] + ELLIPSIS_TEXT
        waf_display_name = f"<b>{waf_name}{YOUR_RESULT_TEXT}</b>"
    elif len(waf_name) > MAX_WAF_NAME_LENGTH:
        waf_display_name = waf_name[:MAX_WAF_NAME_LENGTH - len(ELLIPSIS_TEXT)] + ELLIPSIS_TEXT

    return waf_display_name


def _add_tested_wafs_highlight(fig: go.Figure, _df: pd.DataFrame, current_waf_name: str) -> None:
    """
    Add grey background highlights to all tested WAFs except the current highlighted one.

    Args:
        fig (go.Figure): Plotly Figure object to add highlights to.
        _df (pd.DataFrame): DataFrame containing WAF comparison data.
        current_waf_name (str): Name of the current WAF (to be excluded).
    """
    tested_waf_names = [waf_name for waf_name in load_wafs_config().keys() if waf_name != current_waf_name]
    _add_waf_highlights(fig, _df, tested_waf_names, OTHER_TESTED_WAF_COLOR)


def _add_current_waf_highlight(fig: go.Figure, _df: pd.DataFrame, current_waf_name: str) -> None:
    """
    Add light blue background highlight to the current WAF in the bar chart.

    Args:
        fig (go.Figure): Plotly Figure object to add highlight to.
        _df (pd.DataFrame): DataFrame containing WAF comparison data.
        current_waf_name (str): Name of the current WAF to highlight.
    """
    _add_waf_highlights(fig, _df, [current_waf_name], HIGHLIGHTED_TESTED_WAF_COLOR)


def _add_waf_highlights(fig: go.Figure, _df: pd.DataFrame, waf_names_to_highlight: List[str], color: str) -> None:
    """
    Add highlight shapes to specified WAFs in the bar chart.

    Args:
        fig (go.Figure): Plotly Figure object to add highlights to.
        _df (pd.DataFrame): DataFrame containing WAF comparison data.
        waf_names_to_highlight (List[str]): List of WAF names to highlight.
        color (str): Color to use for the highlight background.
    """
    for y_position, (idx, waf_data) in enumerate(_df.iterrows()):
        waf_name = waf_data[WAF_NAME_COL]
        if waf_name in waf_names_to_highlight and not is_pre_tested_waf_row(waf_data):
            path = _get_highlight_path(y_position)
            fig.add_shape(
                type="path",
                path=path,
                fillcolor=color,
                line=dict(width=0),
                layer="below",
                xref="paper",
                yref="y"
            )


def _get_highlight_path(y_position: float) -> str:
    """
    Build an SVG path for a rounded rectangle used as a row highlight. The rectangle has fixed
    left and right X positions and is vertically centered around the given row on the Y axis.

    Args:
        y_position (float): The Y-axis row index position for the highlight.

    Returns:
        str: SVG path string representing a rounded rectangle.
    """
    y0, y1 = y_position - HIGHLIGHT_Y_OFFSET, y_position + HIGHLIGHT_Y_OFFSET
    rx, ry = HIGHLIGHT_RADIUS_X_PAPER, HIGHLIGHT_RADIUS_Y_CAT

    return (
        f"M {HIGHLIGHT_PAPER_BOUND_START + rx} {y0} "
        f"L {HIGHLIGHT_PAPER_BOUND_END - rx} {y0} "
        f"Q {HIGHLIGHT_PAPER_BOUND_END} {y0} {HIGHLIGHT_PAPER_BOUND_END} {y0 + ry} "
        f"L {HIGHLIGHT_PAPER_BOUND_END} {y1 - ry} "
        f"Q {HIGHLIGHT_PAPER_BOUND_END} {y1} {HIGHLIGHT_PAPER_BOUND_END - rx} {y1} "
        f"L {HIGHLIGHT_PAPER_BOUND_START + rx} {y1} "
        f"Q {HIGHLIGHT_PAPER_BOUND_START} {y1} {HIGHLIGHT_PAPER_BOUND_START} {y1 - ry} "
        f"L {HIGHLIGHT_PAPER_BOUND_START} {y0 + ry} "
        f"Q {HIGHLIGHT_PAPER_BOUND_START} {y0} {HIGHLIGHT_PAPER_BOUND_START + rx} {y0} Z"
    )


def _add_reference_line(fig: go.Figure) -> None:
    """
    Add a vertical reference line at 90% to the chart.

    Args:
        fig (go.Figure): Plotly Figure object to add the reference line to.
    """
    fig.add_vline(
        x=90,
        line_dash="dash",
        line_color=REFERENCE_LINE_COLOR,
        line_width=REFERENCE_LINE_WIDTH,
        annotation_text=REFERENCE_LINE_ANNOTATION,
        annotation_position="bottom",
        annotation_yshift=REFERENCE_LINE_ANNOTATION_YSHIFT,
        annotation_font=dict(size=TEXT_SIZE, color=TEXT_COLOR),
        layer="below"
    )


def get_bar_chart(_df: pd.DataFrame, current_waf_name: str) -> str:
    """
    Generate bar chart comparing tested WAFs and pre-tested WAFs results and return as a base64 image.

    Args:
        _df (pd.DataFrame): DataFrame with WAF comparison data.
        current_waf_name (str): Name of the current WAF to highlight.

    Returns:
        str: Base64 encoded PNG image string of the bar chart.
    """
    fig = _create_bar_chart(_df, current_waf_name)
    bar_chart_base64_image = convert_figure_to_base64(fig, width=1800, height=700, scale=2)
    return bar_chart_base64_image
