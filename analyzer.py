import plotly.express as px
from pathlib import Path
import pandas as pd

from config import engine
from helper import log, isTableExists

COLOR_CONTINUOUS_SCALE = ["#024E1B", "#006B3E", "#FFE733", "#FFAA1C", "#FF8C01", "#ED2938"]


def load_data():
    """
    Loads the results from the DB.
    """

    df_results = pd.read_sql_query("""
    WITH TNR AS (
        SELECT "WAF_Name",
               SUM(CASE WHEN "isBlocked" = False THEN 1.0 ELSE 0.0 END) / count(*) * 100 AS true_negative_rate
        FROM waf_comparison
        WHERE response_status_code != 0 and "DataSetType" = 'Legitimate'
        GROUP BY "WAF_Name"
    ),
        TPR AS (
        SELECT "WAF_Name",
               SUM(CASE WHEN "isBlocked" = True THEN 1.0 ELSE 0.0 END) / count(*) * 100 AS true_positive_rate
        FROM waf_comparison
        WHERE response_status_code != 0 and "DataSetType" = 'Malicious'
        GROUP BY "WAF_Name"
    )
    SELECT TPR."WAF_Name",
           ROUND(100-TNR.true_negative_rate, 3) AS false_positive_rate,
           ROUND(100-TPR.true_positive_rate, 3) AS false_negative_rate,
           ROUND(TPR.true_positive_rate, 3) AS true_positive_rate,
           ROUND(TNR.true_negative_rate, 3) AS true_negative_rate,
           ROUND((TPR.true_positive_rate + TNR.true_negative_rate)/2, 3) AS balanced_accuracy
    FROM TPR
    JOIN TNR on TPR."WAF_Name" = TNR."WAF_Name"
    ORDER BY balanced_accuracy DESC
    """, engine)

    _dff = df_results.rename({
        "WAF_Name": "WAF Name",
        "false_positive_rate": "False Positive Rate",
        "false_negative_rate": "False Negative rate",
        "true_positive_rate": "True Positive Rate",
        "true_negative_rate": "True Negative Rate",
        "balanced_accuracy": "Balanced Accuracy",
    }, axis=1).copy()

    return _dff


def create_graph(_df, metric, is_ascending):
    """
    Creates a plotly html graph and saves it in the Output directory while also printing the results to the console.
    """
    _df_sorted = _df.sort_values(metric, ascending=is_ascending).copy()

    fig = px.bar(
        _df_sorted,
        x=metric,
        y="WAF Name",
        color=metric,
        title=metric + " chart",
        text=metric,
        color_continuous_scale=COLOR_CONTINUOUS_SCALE[::-1] if is_ascending else COLOR_CONTINUOUS_SCALE,
        template='plotly',
        orientation='h',
    ).update_layout(title_x=0.5, font=dict(size=18))

    # Plotly sort visualization is opposite to pandas sort.
    _df_sorted = _df_sorted[::-1]

    _df_sorted['Position'] = range(1, len(_df_sorted) + 1)
    print(f'\n\n{metric}:\n')
    print(_df_sorted[['Position', 'WAF Name', metric]].to_string(index=False))

    Path("Output").mkdir(exist_ok=True)
    fig.write_html(f"Output\\{metric}.html")


def create_2d_graph(_df):
    """
    Creates 2d graph plotly graph visualizing the True Negative Rate with the True Positive Rate.
    """
    fig = px.scatter(
        _df,
        x='True Negative Rate',
        y='True Positive Rate',
        labels={
            "True Negative Rate": "Accuracy (100-False Positive Rate)",
            "True Positive Rate": "Security Coverage (True Positive Rate)"
        },
        color='Balanced Accuracy',
        title="WAF Comparison 2023 - Security Coverage & Accuracy",
        text='WAF Name',
        template='plotly',
        color_continuous_scale=COLOR_CONTINUOUS_SCALE[::-1],

    ).update_layout(title_x=0.5, font=dict(size=16))
    fig.update_traces(textposition="bottom center")

    Path("Output").mkdir(exist_ok=True)
    fig.write_html(f"Output\\2d Graph True Negative Rate & True Positive Rate.html")


def analyze_results():
    # Check if table exits.
    if not isTableExists('waf_comparison'):
        log.warning("Table waf_comparison doesn't exists in the DB, The analyzer was called before the runner.")
        log.warning("Please fill WAFS_DICT configuration in the config.py file and run the script again.")
        return

    _dff = load_data()
    create_graph(_dff, metric='False Positive Rate', is_ascending=False)
    create_graph(_dff, metric='False Negative rate', is_ascending=False)
    create_graph(_dff, metric='True Positive Rate', is_ascending=True)
    create_graph(_dff, metric='True Negative Rate', is_ascending=True)
    create_graph(_dff, metric='Balanced Accuracy', is_ascending=True)
    create_2d_graph(_dff)
    log.info("Graph visualization saved into Output directory.")


if __name__ == '__main__':
    analyze_results()
