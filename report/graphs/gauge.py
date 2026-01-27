import math
from typing import Dict, Any

from .constants import GAUGE_SECURITY_QUALITY_TEXTS, GAUGE_DETECTION_QUALITY_TEXTS
from .utils import get_score_color, get_score_text

CX = 500
CY = 500
RADIUS = 360
STROKE_WIDTH = 30
GAP_DEG = 50
CAP_DEG = 1.0
TICK_LENGTH = 36
TICK_STROKE = 7
TICK_COLOR = '#777777'
TICK_INSET = 12
TICK_X_NUDGE = 14
TICK_Y_NUDGE = -4


def _get_track_angles_and_paths() -> Dict[str, float | str]:
    """
    Compute the start/end angles and SVG paths for the left and right gauge tracks.

    Returns:
        Dict[str, float | str]: Dictionary with start/end angles and SVG paths for left and right tracks.
    """
    top_gap_center = 0.0
    bottom_gap_center = 180.0
    half_g = GAP_DEG / 2.0
    # Right track
    track_right_start = top_gap_center + half_g
    track_right_end = bottom_gap_center - half_g
    track_right_path = _create_svg_arc_path(track_right_start, track_right_end)
    # Left track
    track_left_start = bottom_gap_center + half_g
    track_left_end = 360.0 - top_gap_center - half_g
    track_left_path = _create_svg_arc_path(track_left_start, track_left_end)
    return {
        'track_left_start': track_left_start,
        'track_left_end': track_left_end,
        'track_left_path': track_left_path,
        'track_right_start': track_right_start,
        'track_right_end': track_right_end,
        'track_right_path': track_right_path,
    }


def _get_progress_arc_paths(
        track_left_start: float,
        track_left_end: float,
        left_percentage: float,
        track_right_start: float,
        track_right_end: float,
        right_percentage: float
) -> Dict[str, float | str]:
    """
    Calculate SVG paths for progress arcs, including splitting for square/round caps.

    Args:
        track_left_start (float): Start angle for the left arc.
        track_left_end (float): End angle for the left arc.
        left_percentage (float): Percentage for the left arc (True Positive Rate).
        track_right_start (float): Start angle for the right arc.
        track_right_end (float): End angle for the right arc.
        right_percentage (float): Percentage for the right arc (True Negative Rate).

    Returns:
        Dict[str, float | str]: SVG path strings for left/right progress arcs and their split segments, plus computed end angles.
    """
    # Left progress arc
    left_span = track_left_end - track_left_start
    left_end_angle = track_left_start + (left_span * left_percentage / 100.0)
    progress_left_path = _create_svg_arc_path(track_left_start, left_end_angle)
    left_cap_end_angle = min(left_end_angle, track_left_start + CAP_DEG)
    progress_left_path_square = _create_svg_arc_path(track_left_start,
                                                     left_cap_end_angle) if left_end_angle > track_left_start else ''
    progress_left_path_round = _create_svg_arc_path(left_cap_end_angle,
                                                    left_end_angle) if left_end_angle > left_cap_end_angle else ''

    # Right progress arc
    right_span = track_right_end - track_right_start
    right_start_angle = track_right_end - (right_span * right_percentage / 100.0)
    progress_right_path = _create_svg_arc_path(right_start_angle, track_right_end)
    right_cap_start_angle = max(right_start_angle, track_right_end - CAP_DEG)
    progress_right_path_round = _create_svg_arc_path(right_start_angle,
                                                     right_cap_start_angle) if right_cap_start_angle > right_start_angle else ''
    progress_right_path_square = _create_svg_arc_path(right_cap_start_angle,
                                                      track_right_end) if track_right_end > right_cap_start_angle else ''

    return {
        'progress_left_path': progress_left_path,
        'progress_left_path_square': progress_left_path_square,
        'progress_left_path_round': progress_left_path_round,
        'progress_right_path': progress_right_path,
        'progress_right_path_square': progress_right_path_square,
        'progress_right_path_round': progress_right_path_round,
        'left_end_angle': left_end_angle,
        'right_start_angle': right_start_angle,
    }


def _get_tick_lines(
        track_left_start: float,
        track_left_end: float,
        track_right_start: float,
        track_right_end: float
) -> Dict[str, str]:
    """
    Generate SVG lines for tick marks at arc endpoints.

    Args:
        track_left_start (float): Start angle for the left arc.
        track_left_end (float): End angle for the left arc.
        track_right_start (float): Start angle for the right arc.
        track_right_end (float): End angle for the right arc.

    Returns:
        Dict[str, str]: SVG line elements for tick marks at arc endpoints.
    """
    left_tick_line = _get_tick_line(track_left_start)
    left_end_tick_line = _get_tick_line(track_left_end)
    right_tick_line = _get_tick_line(track_right_start)
    right_end_tick_line = _get_tick_line(track_right_end)
    return {
        'left_tick_line': left_tick_line,
        'left_end_tick_line': left_end_tick_line,
        'right_tick_line': right_tick_line,
        'right_end_tick_line': right_end_tick_line,
    }


def _get_tick_line(angle_deg: float) -> str:
    """
    Create SVG line for a tick mark at a given angle.

    Args:
        angle_deg (float): Angle in degrees.

    Returns:
        str: SVG line element as string.
    """
    base_radius = RADIUS + STROKE_WIDTH / 2 - TICK_INSET
    end = _polar_to_cartesian(CX, CY, base_radius, angle_deg)
    angle_rad = math.radians(angle_deg - 90)
    dx = math.cos(angle_rad)
    dy = math.sin(angle_rad)
    sx = TICK_X_NUDGE if end["x"] < CX else -TICK_X_NUDGE
    sy = TICK_Y_NUDGE if end["y"] < CY else -TICK_Y_NUDGE
    cx_tick = end["x"] + sx
    cy_tick = end["y"] + sy
    x1 = cx_tick - dx * TICK_LENGTH / 2
    y1 = cy_tick - dy * TICK_LENGTH / 2
    x2 = cx_tick + dx * TICK_LENGTH / 2
    y2 = cy_tick + dy * TICK_LENGTH / 2
    return (
        f'<line x1="{x1:.2f}" y1="{y1:.2f}" '
        f'x2="{x2:.2f}" y2="{y2:.2f}" '
        f'stroke="{TICK_COLOR}" stroke-width="{TICK_STROKE}" stroke-linecap="square" />'
    )


def _create_svg_arc_path(start_angle: float, end_angle: float) -> str:
    """
    Create an SVG path for an arc.

    Args:
        start_angle (float): Start angle in degrees.
        end_angle (float): End angle in degrees.

    Returns:
        str: SVG path string.
    """
    start = _polar_to_cartesian(CX, CY, RADIUS, end_angle)
    end = _polar_to_cartesian(CX, CY, RADIUS, start_angle)
    arc_sweep = end_angle - start_angle
    large_arc_flag = "1" if arc_sweep > 180 else "0"
    return (
        f"M {start['x']:.2f} {start['y']:.2f} "
        f"A {RADIUS} {RADIUS} 0 {large_arc_flag} 0 {end['x']:.2f} {end['y']:.2f}"
    )


def _polar_to_cartesian(center_x: float, center_y: float, radius: float, angle_degrees: float) -> Dict[str, float]:
    """
    Convert polar coordinates to cartesian coordinates.

    Args:
        center_x (float): X coordinate of center.
        center_y (float): Y coordinate of center.
        radius (float): Radius from center.
        angle_degrees (float): Angle in degrees (clockwise from 12 o'clock).

    Returns:
        Dict[str, float]: Cartesian coordinates {'x', 'y'}.
    """
    angle_radians = (angle_degrees - 90) * math.pi / 180.0
    return {
        'x': center_x + (radius * math.cos(angle_radians)),
        'y': center_y + (radius * math.sin(angle_radians))
    }


def _get_tp_text(percentage: float) -> str:
    """
    Get bullet text for True Positive Rate.

    Args:
        percentage (float): Percentage value.

    Returns:
        str: Bullet text for True Positive Rate.
    """
    return get_score_text(percentage, GAUGE_SECURITY_QUALITY_TEXTS)


def _get_tn_text(percentage: float) -> str:
    """
    Get bullet text for True Negative Rate.

    Args:
        percentage (float): Percentage value.

    Returns:
        str: Bullet text for True Negative Rate.
    """
    return get_score_text(percentage, GAUGE_DETECTION_QUALITY_TEXTS)


def get_gauge(left_percentage: float, right_percentage: float) -> Dict[str, Any]:
    """
    Generate all geometry, color, and text information required to render a dual-arc gauge.
    Computes SVG paths for the left and right arcs (tracks and progress), tick mark positions,
    and color/text labels for a gauge visualization. The left arc represents the True Positive Rate,
    and the right arc the True Negative Rate.

    Args:
        left_percentage (float): Percentage for the left arc (True Positive Rate).
        right_percentage (float): Percentage for the right arc (True Negative Rate).

    Returns:
        Dict[str, Any]: SVG paths, tick lines, colors, and text labels for rendering the gauge.
    """
    tracks = _get_track_angles_and_paths()
    progress = _get_progress_arc_paths(
        tracks['track_left_start'], tracks['track_left_end'], left_percentage,
        tracks['track_right_start'], tracks['track_right_end'], right_percentage
    )
    ticks = _get_tick_lines(
        tracks['track_left_start'], tracks['track_left_end'],
        tracks['track_right_start'], tracks['track_right_end']
    )
    return {
        "left_percentage": left_percentage,
        "right_percentage": right_percentage,
        "left_bullet": _get_tp_text(left_percentage),
        "right_bullet": _get_tn_text(right_percentage),
        "left_color": get_score_color(left_percentage),
        "right_color": get_score_color(right_percentage),
        "stroke_width": STROKE_WIDTH,
        "track_left_path": tracks['track_left_path'],
        "track_right_path": tracks['track_right_path'],
        "progress_left_path": progress['progress_left_path'],
        "progress_right_path": progress['progress_right_path'],
        "progress_left_path_square": progress['progress_left_path_square'],
        "progress_left_path_round": progress['progress_left_path_round'],
        "progress_right_path_square": progress['progress_right_path_square'],
        "progress_right_path_round": progress['progress_right_path_round'],
        "left_tick_line": ticks['left_tick_line'],
        "left_end_tick_line": ticks['left_end_tick_line'],
        "right_tick_line": ticks['right_tick_line'],
        "right_end_tick_line": ticks['right_end_tick_line'],
    }
