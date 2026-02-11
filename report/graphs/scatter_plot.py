import plotly.graph_objs as go
import pandas as pd

from .constants import YOUR_RESULT_TEXT
from .utils import convert_figure_to_base64, is_pre_tested_waf_row
from helper import load_wafs_config

QUADRANT_LIGHT_COLOR = "rgba(192, 222, 255, 0.8)"
QUADRANT_DARK_COLOR = "rgba(53, 148, 255, 0.4)"
HISTORICAL_WAF_MARKER_COLOR = "rgba(79, 78, 78, 0.8)"
OTHER_TESTED_WAF_MARKER_SIZE = 16
HIGHLIGHT_WAF_MARKER_SIZE = 25
HISTORICAL_WAF_MARKER_SIZE = 11
REFERENCE_LINE_COLOR = "#FFFFFF"
REFERENCE_LINE_WIDTH = 4
HIGHLIGHTED_SYMBOLS = [
    {'symbol': 'diamond-x', 'color': '#f72585', 'stroke': '#b5179e'},
    {'symbol': 'circle-x', 'color': '#70e000', 'stroke': '#006400', },
    {'symbol': 'square-x', 'color': '#5933f2', 'stroke': '#3a0ca3'},
    {'symbol': 'pentagon', 'color': '#4895ef', 'stroke': '#3f37c9'}
]
DEFAULT_NUMERIC_COLOR = '#22223b'
DEFAULT_NUMERIC_STROKE = '#4a4e69'


def _prepare_graph_dataframe(_df: pd.DataFrame) -> pd.DataFrame:
    """
    Prepare dataframe for 2D scatter plot visualization.
    Clips values to axis minimums so points below threshold are shown at the axis edge.

    Args:
        _df (pd.DataFrame): Original DataFrame with WAF metrics.

    Returns:
        pd.DataFrame: DataFrame with clipped values.
    """
    clipped_df = _df.copy()

    clipped_df['True Negative Rate'] = clipped_df['True Negative Rate'].clip(lower=40)
    clipped_df['True Positive Rate'] = clipped_df['True Positive Rate'].clip(lower=10)

    return clipped_df


def _create_scatter_plot(_df: pd.DataFrame, highlighted_waf_name: str) -> go.Figure:
    """
    Create a Plotly scatter plot comparing WAF performance.

    X-axis: True Negative Rate
    Y-axis: True Positive Rate

    Pre-tested WAFs are shown with grey markers, annotations and absolute positions.
    Tested WAFs are shown with unique colored markers, with one highlighted WAF.

    Args:
        _df (pd.DataFrame): DataFrame with WAF metrics and marker/label columns.
        highlighted_waf_name (str): Name of the WAF to highlight with larger marker.

    Returns:
        go.Figure: Plotly figure object for the scatter plot.
    """
    fig = go.Figure()
    _get_configure_2d_graph_layout(fig)
    _configure_axes(fig)
    _add_reference_lines(fig)
    _add_quadrant_shading(fig)
    _add_pre_tested_wafs_annotations(fig, _df)
    _add_tested_wafs(fig, _df, highlighted_waf_name)
    _add_pre_tested_wafs_points(fig, _df)

    return fig


def _get_configure_2d_graph_layout(fig: go.Figure) -> None:
    """
    Updates the scatter plot figure with main layout and legend.

    Args:
        fig (go.Figure): Plotly figure object to update.
    """
    layout_config = _get_2d_graph_layout_config()
    legend_config = _get_legend_config()
    fig.update_layout(**layout_config)
    fig.update_layout(showlegend=True, coloraxis_showscale=False)
    fig.update_layout(legend=legend_config)


def _get_2d_graph_layout_config() -> dict:
    """
    Get layout options for the 2D scatter plot.

    Returns:
        dict: Layout configuration dictionary for Plotly.
    """
    return {
        'title_x': 0.5,
        'font': dict(size=14),
        'margin': dict(l=80, r=80, t=100, b=80),
        'paper_bgcolor': 'rgba(255,255,255,1)',
        'plot_bgcolor': 'rgba(235,244,255,1)',
        'coloraxis_colorbar': dict(orientation='h', x=0.5, xanchor='center', y=1, yanchor='bottom', len=0.5,
                                   thickness=20),
        'xaxis': dict(showgrid=True, zeroline=False, title=dict(font=dict(size=22)), tickfont=dict(size=16)),
        'yaxis': dict(showgrid=True, zeroline=False, title=dict(font=dict(size=22)), tickfont=dict(size=16)),
        'showlegend': False
    }


def _get_legend_config() -> dict:
    """
    Get legend configuration for the scatter plot.

    Returns:
        dict: Legend configuration dictionary for Plotly.
    """
    return dict(
        orientation="h",
        yanchor="bottom",
        y=1.02,
        xanchor="center",
        x=0.5,
        font=dict(size=18)
    )


def _configure_axes(fig: go.Figure) -> None:
    """
    Configure axes for the scatter plot and add axis labels.

    Args:
        fig (go.Figure): Plotly figure object.
    """
    fig.update_xaxes(title_text="Detection Quality (True Negative)", range=[40, 100],
                     tickmode='array', tickvals=[40, 50, 60, 70, 80, 90, 95, 100], constrain='range',
                     showgrid=False)
    fig.update_yaxes(title_text="Security Quality (True Positive)", range=[10, 100],
                     tickmode='array', tickvals=[10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 100], constrain='range',
                     showgrid=False)

    # Add custom grid lines that skip x=95 and y=95
    for x_val in [40, 50, 60, 70, 80, 90, 100]:
        fig.add_shape(
            type="line",
            xref="x", yref="paper",
            x0=x_val, x1=x_val, y0=0, y1=1,
            line=dict(color='rgba(255, 255, 255, 0.5)', width=2),
            layer="below"
        )

    for y_val in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]:
        fig.add_shape(
            type="line",
            xref="paper", yref="y",
            x0=0, x1=1, y0=y_val, y1=y_val,
            line=dict(color='rgba(255, 255, 255, 0.5)', width=2),
            layer="below"
        )


def _add_reference_lines(fig: go.Figure) -> None:
    """
    Add 90% threshold reference lines to the scatter plot.

    Args:
        fig (go.Figure): Plotly figure object to add reference lines to.
    """
    fig.add_hline(y=90, line_dash="dash", line_color=REFERENCE_LINE_COLOR, line_width=REFERENCE_LINE_WIDTH)
    fig.add_vline(x=90, line_dash="dash", line_color=REFERENCE_LINE_COLOR, line_width=REFERENCE_LINE_WIDTH)


def _add_quadrant_shading(fig: go.Figure) -> None:
    """
    Add shaded quadrant rectangles to the scatter plot.

    Args:
        fig (go.Figure): Plotly figure object to add shapes to.
    """
    # light blue block: 80–100 on both axes
    fig.add_shape(
        type="rect",
        xref="x", yref="y",
        x0=80, x1=100, y0=80, y1=100,
        line=dict(width=0),
        fillcolor="#C4DCFF",
        layer="below",
        opacity=0.4
    )
    # darker blue block: 90–100 on both axes
    fig.add_shape(
        type="rect",
        xref="x", yref="y",
        x0=90, x1=100, y0=90, y1=100,
        line=dict(width=0),
        fillcolor="#A6CAFF",
        layer="below",
        opacity=0.4
    )
    # small 95-100 rectangle
    fig.add_shape(
        type="rect",
        xref="x", yref="y",
        x0=95, x1=100, y0=95, y1=100,
        line=dict(width=0),
        fillcolor="#5EA1FD",
        layer="below",
        opacity=0.4
    )


def _add_pre_tested_wafs_annotations(fig: go.Figure, _df: pd.DataFrame) -> None:
    """
    Add arrow annotations for pre-tested WAFs data points with hard-coded positions.

    Args:
        fig (go.Figure): Plotly figure object to add annotations to.
        _df (pd.DataFrame): DataFrame containing WAF data with 'is_pre_tested' flag.
    """
    # Hard-coded annotation positions for each pre-tested WAF - (dx, dy, xanchor, showarrow)
    annotation_nudges = {
        "Microsoft Azure WAF - Default (OWASP 3.2 Ruleset)": (0.5, -1.4, "left", False),
        "Google Cloud Armor - Preconfigured ModSecurity Rules": (0.5, -1.4, "left", False),
        "CloudFlare WAF - Default Managed + OWASP Core Rulesets": (-0.1, -19, "right", True),
        "AWS WAF - Default Managed": (-3.4, -8, "right", True),
        "AWS WAF - Default Managed + F5 Ruleset": (-7, 0, "right", True),
        "NGINX ModSecurity - Default (CRS 4.20.0 Ruleset)": (2, -1.4, "right", False),
        "F5 NGINX App Protect - Default Profile": (-2, -6, "center", True),
        "F5 NGINX App Protect - Strict Profile": (-0.5, -1.4, "right", False),
        "F5 BIG-IP Advanced WAF - Rapid Deployment Policy": (-2.8, -20.5, "right", True),
        "open-appsec / CloudGuard WAF - Default (High Confidence)": (-2.4, -1.9, "right", True),
        "open-appsec / CloudGuard WAF - Critical Confidence": (-2.8, -8, "right", True),
        "Imperva Cloud WAF (2025) - Default Configuration": (-0.5, 1, "right", False),
        "FortiAppSec Cloud - Default Configuration": (-0.5, -1.4, "right", False),
        "Barracuda - Default Configuration": (3, -1, "right", False),
    }

    for _, row in _df.iterrows():
        if not is_pre_tested_waf_row(row):
            continue
        waf_name = row['WAF Name']
        if waf_name not in annotation_nudges:
            continue

        x_pos = row['True Negative Rate']
        y_pos = row['True Positive Rate']
        dx, dy, xanchor, show_arrow = annotation_nudges[waf_name]

        parts = waf_name.split(" - ", 1)
        formatted_text = f"<b>{parts[0]}</b><br>{parts[1]}" if len(parts) == 2 else f"<b>{waf_name}</b>"

        if show_arrow:
            fig.add_annotation(
                x=x_pos, y=y_pos,
                ax=x_pos + dx, ay=y_pos + dy,
                xref="x", yref="y", axref="x", ayref="y",
                text=formatted_text, showarrow=True,
                xanchor=xanchor, yanchor="middle",
                arrowhead=2, arrowsize=1, arrowwidth=2, arrowcolor=HISTORICAL_WAF_MARKER_COLOR,
                font=dict(size=22, color=HISTORICAL_WAF_MARKER_COLOR),
                align="left", bgcolor="rgba(255, 255, 255, 0)", borderpad=0,
                opacity=0.72,
                standoff=6
            )
        else:
            fig.add_annotation(
                x=x_pos + dx, y=y_pos + dy,
                xref="x", yref="y",
                text=formatted_text, showarrow=False,
                xanchor=xanchor, yanchor="middle",
                font=dict(size=22, color=HISTORICAL_WAF_MARKER_COLOR),
                align="left", bgcolor="rgba(255, 255, 255, 0)", borderpad=0,
                opacity=0.72
            )


def _add_tested_wafs(fig: go.Figure, _df: pd.DataFrame, highlighted_waf_name: str) -> None:
    """
    Add tested WAFs data points to the scatter plot, highlighting one WAF.

    Args:
        fig (go.Figure): Plotly figure object.
        _df (pd.DataFrame): DataFrame containing WAF data.
        highlighted_waf_name (str): Name of the highlighted WAF.
    """
    sorted_wafs_by_score, waf_to_config = _get_sorted_wafs_and_configs(_df)
    _add_highlighted_waf(fig, _df, highlighted_waf_name, sorted_wafs_by_score, waf_to_config)
    _add_non_highlighted_wafs(fig, _df, highlighted_waf_name, sorted_wafs_by_score, waf_to_config)


def _get_sorted_wafs_and_configs(_df: pd.DataFrame) -> tuple[list[str], dict[str, dict]]:
    """
    Sort WAFs by Balanced Accuracy and assign marker configs for each WAF.

    Args:
        _df (pd.DataFrame): DataFrame containing WAF data.

    Returns:
        tuple: (sorted_wafs_by_score, waf_to_config)
            sorted_wafs_by_score (list): WAF names sorted by Balanced Accuracy (desc).
            waf_to_config (dict): Mapping from WAF name to marker config dict.
    """
    tested_waf_names = list(load_wafs_config().keys())
    waf_names_in_df = [waf for waf in tested_waf_names if waf in _df['WAF Name'].tolist()]
    # Sort WAFs by Balanced Accuracy (descending), with original index as tiebreaker
    waf_data_with_index = {}
    for idx, row in _df.iterrows():
        waf = row['WAF Name']
        if waf in waf_names_in_df:
            waf_data_with_index[waf] = (row['Balanced Accuracy'], idx)
    # Sort by balanced accuracy (desc), then by negative index (to preserve DB order on ties)
    sorted_wafs_by_score = sorted(
        waf_data_with_index.keys(),
        key=lambda w: (waf_data_with_index[w][0], -waf_data_with_index[w][1]),
        reverse=True
    )
    # Assign symbols based on balanced accuracy score (dec): first 4 get HIGHLIGHTED_SYMBOLS, rest get incrementing numbers as text
    waf_to_config = {}
    for i, waf_name in enumerate(sorted_wafs_by_score):
        if i < len(HIGHLIGHTED_SYMBOLS):
            waf_to_config[waf_name] = HIGHLIGHTED_SYMBOLS[i]
        else:
            number_marker = str(i + 1)
            waf_to_config[waf_name] = {
                'symbol': 'text',  # plotly text marker
                'color': DEFAULT_NUMERIC_COLOR,
                'stroke': DEFAULT_NUMERIC_STROKE,
                'text': number_marker
            }
    return sorted_wafs_by_score, waf_to_config


def _add_highlighted_waf(fig, _df, highlighted_waf_name, sorted_wafs_by_score, waf_to_config):
    """
    Add the highlighted WAF to the figure with a larger marker and special legend.

    Args:
        fig (go.Figure): Plotly figure object.
        _df (pd.DataFrame): DataFrame containing WAF data.
        highlighted_waf_name (str): Name of the highlighted WAF.
        sorted_wafs_by_score (list): Sorted WAF names by score.
        waf_to_config (dict): Marker configs for each WAF.
    """
    for legend_rank, waf_name in enumerate(sorted_wafs_by_score):
        if waf_name != highlighted_waf_name:
            continue
        row = _get_waf_row(_df, waf_name)
        if row is None:
            continue
        symbol_config = waf_to_config[waf_name]
        trace = _create_waf_trace(row, symbol_config, HIGHLIGHT_WAF_MARKER_SIZE, legend_rank, waf_name,
                                  is_highlighted=True)
        fig.add_trace(trace)


def _add_non_highlighted_wafs(fig, _df, highlighted_waf_name, sorted_wafs_by_score, waf_to_config):
    """
    Add non-highlighted WAFs to the figure with regular markers and legend.

    Args:
        fig (go.Figure): Plotly figure object.
        _df (pd.DataFrame): DataFrame containing WAF data.
        highlighted_waf_name (str): Name of the highlighted WAF.
        sorted_wafs_by_score (list): Sorted WAF names by score.
        waf_to_config (dict): Marker configs for each WAF.
    """
    for legend_rank, waf_name in enumerate(sorted_wafs_by_score):
        if waf_name == highlighted_waf_name:
            continue
        row = _get_waf_row(_df, waf_name)
        if row is None:
            continue
        symbol_config = waf_to_config[waf_name]
        trace = _create_waf_trace(row, symbol_config, OTHER_TESTED_WAF_MARKER_SIZE, legend_rank, waf_name)
        fig.add_trace(trace)


def _get_waf_row(_df: pd.DataFrame, waf_name: str) -> pd.Series | None:
    """
    Extract the row for a given WAF name from the DataFrame.

    Args:
        _df (pd.DataFrame): DataFrame containing WAF data.
        waf_name (str): Name of the WAF to extract.

    Returns:
        pd.Series or None: The row for the WAF, or None if not found.
    """
    waf_row = _df[_df['WAF Name'] == waf_name]
    if waf_row.empty:
        return None
    return waf_row.iloc[0]


def _create_waf_trace(row: pd.Series, symbol_config: dict, marker_size: int, legend_rank: int, waf_name: str,
                      is_highlighted: bool = False) -> go.Scatter:
    """
    Create a Plotly Scatter trace for a WAF data point.

    Args:
        row (pd.Series): Row containing WAF metrics.
        symbol_config (dict): Marker config for the WAF.
        marker_size (int): Size of the marker.
        legend_rank (int): Legend order for the WAF.
        waf_name (str): Name of the WAF.
        is_highlighted (bool): Whether this is the highlighted WAF.

    Returns:
        go.Scatter: Plotly scatter trace for the WAF.
    """
    if symbol_config['symbol'] == 'text':
        legend_number = symbol_config['text']
        name = f"<b>#{legend_number}: {waf_name}{YOUR_RESULT_TEXT}</b>" if is_highlighted else f"#{legend_number}: {waf_name}"
        return go.Scatter(
            x=[row['True Negative Rate']],
            y=[row['True Positive Rate']],
            mode='markers+text',
            marker=dict(
                size=marker_size,
                color='white',
                symbol='circle',
                line=dict(width=2, color='black'),
            ),
            text=[legend_number],
            textposition='middle center',
            textfont=dict(size=marker_size * 0.7, color='black', family='Arial', ),
            name=name,
            showlegend=True,
            legendgroup=waf_name,
            legendrank=legend_rank,
            hoverinfo='skip',
            cliponaxis=False,
        )
    else:
        name = f"<b>{waf_name}{YOUR_RESULT_TEXT}</b>" if is_highlighted else waf_name
        return go.Scatter(
            x=[row['True Negative Rate']],
            y=[row['True Positive Rate']],
            mode='markers',
            marker=dict(
                size=marker_size,
                color=symbol_config['color'],
                symbol=symbol_config['symbol'],
                line=dict(width=2, color=symbol_config['stroke'])
            ),
            name=name,
            showlegend=True,
            legendgroup=waf_name,
            legendrank=legend_rank,
            hoverinfo='skip',
            cliponaxis=False
        )


def _add_pre_tested_wafs_points(fig: go.Figure, _df: pd.DataFrame) -> None:
    """
    Add pre-tested WAFs data points as a trace to the scatter plot.

    Args:
        fig (go.Figure): Plotly figure object to add the trace to.
        _df (pd.DataFrame): DataFrame containing WAF data with 'is_pre_tested' flag.
    """
    pre_tested_wafs_df = _df[[is_pre_tested_waf_row(row) for _, row in _df.iterrows()]]
    if not pre_tested_wafs_df.empty:
        fig.add_trace(go.Scatter(
            x=pre_tested_wafs_df['True Negative Rate'],
            y=pre_tested_wafs_df['True Positive Rate'],
            mode='markers',
            marker=dict(
                size=HISTORICAL_WAF_MARKER_SIZE,
                color=HISTORICAL_WAF_MARKER_COLOR,
                symbol='circle',
                line=dict(width=0),
                opacity=0.72
            ),
            name="Pre-tested WAFs",
            showlegend=True,
            hoverinfo='skip',
            cliponaxis=False
        ))


def get_scatter_plot_graph(_df: pd.DataFrame, highlighted_waf_name: str) -> str:
    """
    Create a 2D scatter plot comparing all WAFs with one highlighted.

    The graph shows the relationship between:
    - True Negative Rate (X-axis): How well the WAF allows legitimate traffic
    - True Positive Rate (Y-axis): How well the WAF blocks malicious traffic

    The highlighted WAF appears with a larger marker for easy identification.

    Args:
        _df (pd.DataFrame): DataFrame containing WAF comparison metrics.
        highlighted_waf_name (str): Name of the WAF to emphasize in the visualization.

    Returns:
        str: Base64 encoded PNG image string of the scatter plot.
    """
    prepared_df = _prepare_graph_dataframe(_df)
    fig = _create_scatter_plot(prepared_df, highlighted_waf_name)
    scatter_plot_base64_image = convert_figure_to_base64(fig, width=1800, height=1050, scale=3)
    return scatter_plot_base64_image
