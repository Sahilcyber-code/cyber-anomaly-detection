import numpy as np
import pandas as pd

SUSPICIOUS_KEYWORDS = ['wp-login', 'phpmyadmin', '.env', 'admin', 'cgi-bin', 'server-status']


def compute_features(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate log lines per IP and engineer security features."""
    df = df.copy()
    # ensure timestamp is datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    def suspicious_count(paths):
        count = 0
        for p in paths:
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in p:
                    count += 1
                    break
        return count

    grouped = df.groupby('ip')
    agg = grouped.agg(
        requests=('ip', 'count'),
        unique_paths=('path', lambda x: x.nunique()),
        avg_bytes=('bytes', 'mean'),
        min_ts=('timestamp', 'min'),
        max_ts=('timestamp', 'max'),
        status_list=('status', list),
        paths_list=('path', list),
    )

    # compute counts
    agg['4xx_count'] = agg['status_list'].apply(lambda lst: sum(1 for s in lst if 400 <= s < 500))
    agg['5xx_count'] = agg['status_list'].apply(lambda lst: sum(1 for s in lst if 500 <= s < 600))
    agg['error_count'] = agg['4xx_count'] + agg['5xx_count']
    agg['suspicious_path_hits'] = agg['paths_list'].apply(suspicious_count)

    # time window and rates
    agg['time_window_sec'] = (agg['max_ts'] - agg['min_ts']).dt.total_seconds()
    agg['time_window_sec'] = agg['time_window_sec'].replace(0, 1)
    agg['req_per_sec'] = agg['requests'] / agg['time_window_sec']
    agg['error_rate'] = agg['error_count'] / agg['requests']

    # log1p transforms
    agg['log_requests'] = np.log1p(agg['requests'])
    agg['log_unique_paths'] = np.log1p(agg['unique_paths'])
    agg['log_suspicious_path_hits'] = np.log1p(agg['suspicious_path_hits'])
    agg['log_req_per_sec'] = np.log1p(agg['req_per_sec'])

    # drop helper columns
    agg = agg.reset_index()
    agg = agg.drop(columns=['status_list', 'paths_list', 'min_ts', 'max_ts'])
    return agg
