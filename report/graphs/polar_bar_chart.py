import sys
from typing import List, Tuple

import plotly.graph_objects as go
import pandas as pd
from logger import log

from .constants import DETAILED_COLOR_SCALE, DETAILED_COLOR_BOUNDS
from .utils import convert_figure_to_base64, format_score

TEXT_COLOR = '#5D6B82'
TEXT_SIZE = 13
MAX_PERCENT = 100
CHAR_TO_DEG = 1.0
BASE_POLAR = "polar"  # rings + tick labels
TOP_POLAR = "polar2"  # colored slices + category labels
ANGLES_START_OFFSET_DEGREES = 90
ANGLES_GAP_RATIO = 0.0
ANCHOR_CHARS_TO_DEG = CHAR_TO_DEG
COLOR_SCALE_CMIN = 0
COLOR_SCALE_CMAX = 100


def _create_polar_bar_chart(items: pd.DataFrame) -> go.Figure:
    """
    Create a polar bar chart Plotly figure from a DataFrame.

    Args:
        items (pd.DataFrame): DataFrame with 2 columns (category, value).

    Returns:
        go.Figure: Plotly Figure object for the polar bar chart.
    """
    labels, display_values = _validate_and_extract_polar_items(items)
    bar_trace, thetas = _build_polar_bar_trace(labels, display_values)
    label_traces = _build_label_traces(labels, display_values, thetas)
    tick_traces = _build_centered_tick_labels()
    fig = go.Figure([tick_traces, bar_trace, *label_traces])
    fig.update_layout(**get_layout_props())
    return fig


def _validate_and_extract_polar_items(items: pd.DataFrame) -> Tuple[List[str], List[int | float]]:
    """
    Validate the input DataFrame for a polar bar chart and extract labels and display values.

    Args:
        items (pd.DataFrame): DataFrame with exactly 2 columns. The first column is treated as category labels, the second as values.

    Returns:
        Tuple[List[str], List[int | float]]: A tuple containing a list of string labels and a list of float/int display values (floored to one decimal place).
    """
    if items.shape[1] != 2:
        log.error(
            "Polar bar chart input must be a DataFrame with exactly 2 columns: one for category and one for value.")
        sys.exit()
    labels = items.iloc[:, 0].astype(str).tolist()
    display_values = [format_score(val) for val in items.iloc[:, 1]]
    return labels, display_values


def _build_polar_bar_trace(labels: List[str], display_values: List[int | float]) -> Tuple[go.Barpolar, List[float]]:
    """
    Create the radial bars for the polar bar chart.

    Args:
        labels (List[str]): List of category labels.
        display_values (List[int | float]): List of values for each label.

    Returns:
        Tuple[go.Barpolar, List[float]]: Barpolar trace and list of theta angles.
    """
    color_vals = display_values[:]
    thetas, widths = _angles_and_widths(len(labels))
    colorscale = _make_colorscale()
    bar_trace = go.Barpolar(
        r=display_values,
        theta=thetas,
        width=widths,
        marker=dict(
            color=color_vals,
            colorscale=colorscale,
            cmin=COLOR_SCALE_CMIN,
            cmax=COLOR_SCALE_CMAX,
            line=dict(width=1, color='rgba(255, 255, 255, 0.3)'),
        ),
        opacity=0.8,
        showlegend=False,
        name='',
        subplot=TOP_POLAR,
    )
    return bar_trace, thetas


def _angles_and_widths(n: int) -> Tuple[List[float], List[float]]:
    """
    Compute equally spaced angles and widths around the circle.

    Args:
        n (int): Number of sectors.

    Returns:
        Tuple[List[float], List[float]]: Tuple of (thetas, widths).
    """
    if n <= 0:
        return [], []
    full = 360.0
    slot = full / n
    width = slot * (1.0 - ANGLES_GAP_RATIO)
    thetas = [ANGLES_START_OFFSET_DEGREES + i * slot for i in range(n)]
    widths = [width] * n
    return thetas, widths


def _make_colorscale() -> List[Tuple[float, str]]:
    """
    Build a Plotly-compatible colorscale.

    Returns:
        List[Tuple[float, str]]: List of (position, color) tuples for Plotly colorscale.
    """
    colors = DETAILED_COLOR_SCALE
    color_bounds = DETAILED_COLOR_BOUNDS
    n = len(colors)
    if n == 1:
        return [(0.0, colors[0]), (1.0, colors[0])]
    span = (COLOR_SCALE_CMAX - COLOR_SCALE_CMIN) or 1.0

    def norm(v: float) -> float:
        return (v - COLOR_SCALE_CMIN) / span

    if not color_bounds:
        step = span / n
        color_bounds = [COLOR_SCALE_CMIN + i * step for i in range(n + 1)]
    stops: List[Tuple[float, str]] = []
    for i in range(n):
        left = norm(color_bounds[i])
        right = norm(color_bounds[i + 1])
        right = min(1.0, right)
        stops.append((left, colors[i]))
        stops.append((right, colors[i]))
    return stops


def _make_label_trace(r: list, theta: list, text: list) -> go.Scatterpolar:
    """
    Helper to create a Scatterpolar trace for labels with common configuration.

    Args:
        r (list): Radial positions.
        theta (list): Angular positions.
        text (list): Text labels.

    Returns:
        go.Scatterpolar: Configured Scatterpolar trace for labels.
    """
    return go.Scatterpolar(
        r=r,
        theta=theta,
        mode='text',
        text=text,
        textposition='middle center',
        textfont=dict(size=TEXT_SIZE, color=TEXT_COLOR, family='Inter, sans-serif'),
        hoverinfo='skip',
        showlegend=False,
        name='',
        cliponaxis=False,
        subplot=TOP_POLAR,
    )


def _build_label_traces(labels: List[str], display_values: List[float], thetas: List[float]) -> List[go.Scatterpolar]:
    """
    Build label traces for the polar bar chart.

    Args:
        labels (List[str]): List of category labels.
        display_values (List[float]): List of values for each label.
        thetas (List[float]): List of theta angles.

    Returns:
        List[go.Scatterpolar]: List of Scatterpolar traces for labels.
    """
    label_inside_threshold = 80  # percent - labels placed inside the slice
    static_ring_threshold = 40  # percent - labels placed on static 45% ring
    texts = [f'<b>{lbl}</b><br>{v}%' for lbl, v in zip(labels, display_values)]
    labels_inside_slice_idxs = [i for i, v in enumerate(display_values) if v > label_inside_threshold]
    labels_outside_slice_idxs = [i for i, v in enumerate(display_values) if
                                 label_inside_threshold >= v > static_ring_threshold]
    labels_on_static_ring_idxs = [i for i, v in enumerate(display_values) if v <= static_ring_threshold]
    traces = []

    if labels_inside_slice_idxs:
        r_inside = [display_values[i] * 0.6 for i in labels_inside_slice_idxs]
        theta_inside = [thetas[i] for i in labels_inside_slice_idxs]
        text_inside = [texts[i] for i in labels_inside_slice_idxs]
        traces.append(_make_label_trace(r_inside, theta_inside, text_inside))
    if labels_outside_slice_idxs:
        r_outside = [min(float(MAX_PERCENT + 6), display_values[i] + 2) for i in labels_outside_slice_idxs]
        theta_outside = [thetas[i] for i in labels_outside_slice_idxs]
        text_outside = [texts[i] for i in labels_outside_slice_idxs]
        traces.append(_make_label_trace(r_outside, theta_outside, text_outside))
    if labels_on_static_ring_idxs:
        # Place all labels for values below 40% on the 45% ring to prevent overlap
        r_static_ring = [45.0] * len(labels_on_static_ring_idxs)
        theta_static_ring = [thetas[i] for i in labels_on_static_ring_idxs]
        text_static_ring = [texts[i] for i in labels_on_static_ring_idxs]
        traces.append(_make_label_trace(r_static_ring, theta_static_ring, text_static_ring))
    return traces


def _build_centered_tick_labels() -> go.Scatterpolar:
    """
    Build a Scatterpolar trace for centered tick labels.

    Returns:
        go.Scatterpolar: Scatterpolar trace for tick labels.
    """
    tick_vals = [i for i in range(10, MAX_PERCENT + 1, 10)]
    return go.Scatterpolar(
        r=tick_vals,
        theta=[270] * len(tick_vals),
        mode='text',
        text=[f'{v}%' for v in tick_vals],
        textposition='middle center',
        textfont=dict(size=TEXT_SIZE - 2, color="rgba(93, 107, 130, 0.7)", family='Inter, sans-serif'),
        hoverinfo='skip',
        showlegend=False,
        name='',
        cliponaxis=False,
    )


def get_layout_props() -> dict:
    """
    Get layout properties for the polar bar chart.

    Returns:
        dict: Layout dictionary for Plotly figure.
    """
    base_polar = dict(
        bgcolor='rgba(255,255,255,1)',
        hole=0.0,
        angularaxis=dict(
            showgrid=False,
            showticklabels=False,
            ticks='',
            direction='clockwise',
            rotation=0,
            linewidth=1.2,
            showline=True,
            linecolor='rgba(210,216,227,0.7)',
            layer='below traces',
        ),
        radialaxis=dict(
            range=[0, MAX_PERCENT],
            visible=True,
            gridcolor='rgba(210,216,227,0.6)',
            gridwidth=1,
            showline=False,
            ticksuffix='%',
            angle=90,
            tickangle=90,
            tickfont=dict(size=TEXT_SIZE - 2, color=TEXT_COLOR),
            tickvals=[i for i in range(10, MAX_PERCENT + 1, 10)],
            ticktext=[f'{i}%' for i in range(10, MAX_PERCENT + 1, 10)],
            showticklabels=False,
            layer='below traces',
        ),
        bargap=0.0,
        domain=dict(x=[0, 1], y=[0, 1]),
    )
    top_polar = dict(
        bgcolor='rgba(0,0,0,0)',
        hole=0.0,
        angularaxis=dict(
            showgrid=False, showticklabels=False, ticks='',
            direction='clockwise', rotation=0, showline=False
        ),
        radialaxis=dict(
            range=[0, MAX_PERCENT],
            showgrid=False, showticklabels=False, showline=False
        ),
        bargap=0.0,
        domain=dict(x=[0, 1], y=[0, 1]),
    )
    return dict(
        font=dict(size=TEXT_SIZE, color=TEXT_COLOR, family='Inter, sans-serif'),
        paper_bgcolor='rgba(255,255,255,1)',
        plot_bgcolor='rgba(255,255,255,1)',
        margin=dict(t=10, b=10, l=10, r=10),
        height=450,
        width=450,
        polar=base_polar,
        polar2=top_polar,
        legend=dict(
            x=1.02, y=0.5, xanchor='left', yanchor='middle',
            bgcolor='rgba(255,255,255,0)', bordercolor='rgba(0,0,0,0)', borderwidth=0,
        ),
    )


def get_polar_bar_chart(items: pd.DataFrame) -> str:
    """
    Generate a polar bar chart as a base64-encoded PNG image string.

    Args:
        items (pd.DataFrame): DataFrame with exactly 2 columns (category, value).

    Returns:
        str: Base64 encoded PNG image string of the polar bar chart.
    """
    fig = _create_polar_bar_chart(items)
    polar_bar_chart_base64_image = convert_figure_to_base64(fig, width=450, height=450, scale=3)
    return polar_bar_chart_base64_image
