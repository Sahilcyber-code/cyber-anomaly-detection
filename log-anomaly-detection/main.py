import os
import pandas as pd

from src.parse_logs import parse_log_file
from src.features import compute_features
from src.train_detect import train_and_detect, generate_report
from src.visualize import plot_top_scores, plot_requests_vs_4xx


def ensure_dirs():
    for d in ['data', 'outputs']:
        os.makedirs(d, exist_ok=True)


def main():
    ensure_dirs()
    log_path = os.path.join('data', 'sample_access.log')
    parsed_csv = os.path.join('data', 'logs.csv')
    anomalies_csv = os.path.join('outputs', 'anomalies.csv')
    report_txt = os.path.join('outputs', 'report.txt')
    score_plot = os.path.join('outputs', 'top_anomalies_score.png')
    scatter_plot = os.path.join('outputs', 'requests_vs_4xx.png')

    print('Parsing logs...')
    df = parse_log_file(log_path)
    df.to_csv(parsed_csv, index=False)

    print('Engineering features...')
    features = compute_features(df)

    print('Training model and detecting anomalies...')
    results = train_and_detect(features)
    results.to_csv(anomalies_csv, index=False)

    print('Generating report...')
    generate_report(results, report_txt)

    print('Creating visualizations...')
    plot_top_scores(results, score_plot)
    plot_requests_vs_4xx(results, scatter_plot)

    print('Done. Outputs written to outputs/ directory.')


if __name__ == '__main__':
    main()
