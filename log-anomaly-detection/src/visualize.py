import matplotlib.pyplot as plt
import pandas as pd


def plot_top_scores(df: pd.DataFrame, output_path: str, top_n: int = 20) -> None:
    df = df.copy()
    df = df.sort_values('anomaly_score')
    data = df.head(top_n)
    plt.figure(figsize=(8, 6))
    plt.barh(data['ip'], data['anomaly_score'], color='red')
    plt.xlabel('Anomaly Score (lower = more anomalous)')
    plt.title('Top anomalous IPs')
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_requests_vs_4xx(df: pd.DataFrame, output_path: str) -> None:
    plt.figure(figsize=(8, 6))
    plt.scatter(df['requests'], df['4xx_count'], c=df['is_anomaly'], cmap='coolwarm', alpha=0.7)
    plt.xlabel('Total Requests')
    plt.ylabel('4xx Error Count')
    plt.title('Requests vs 4xx Errors (color=anomaly)')
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
