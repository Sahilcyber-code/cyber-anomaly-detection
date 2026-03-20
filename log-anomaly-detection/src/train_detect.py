from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
from typing import Tuple

FEATURE_COLUMNS = [
    'requests',
    'unique_paths',
    '4xx_count',
    '5xx_count',
    'error_count',
    'suspicious_path_hits',
    'avg_bytes',
    'time_window_sec',
    'req_per_sec',
    'error_rate',
    'log_requests',
    'log_unique_paths',
    'log_suspicious_path_hits',
    'log_req_per_sec',
]


def train_and_detect(df: pd.DataFrame, contamination: float = 0.20) -> pd.DataFrame:
    """Train IsolationForest and return df with scores and anomaly flag."""
    X = df[FEATURE_COLUMNS].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(X_scaled)
    scores = model.decision_function(X_scaled)
    preds = model.predict(X_scaled)
    # In IsolationForest, anomalies are -1
    df = df.copy()
    df['anomaly_score'] = scores
    df['is_anomaly'] = (preds == -1).astype(int)
    # sort lowest score first
    df = df.sort_values('anomaly_score')
    return df


def generate_report(df: pd.DataFrame, output_path: str, top_n: int = 10) -> None:
    """Write a simple text report to output_path."""
    anomalies = df[df['is_anomaly'] == 1]
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('Top suspicious IPs based on anomaly score\n')
        f.write('=======================================\n')
        for idx, row in anomalies.head(top_n).iterrows():
            f.write(f"{row['ip']}: score={row['anomaly_score']:.4f}, requests={row['requests']}, errors={row['error_count']}, suspicious_hits={row['suspicious_path_hits']}\n")
        f.write('\nInterpretation hints:\n')
        f.write('- Low anomaly score → more unusual behavior compared to population.\n')
        f.write('- Look for high error rates, suspicious path accesses, or very high request rates.\n')
        f.write('- Investigate these IPs in SIEM/vendors for potential intrusions or scans.\n')
