import dash
from dash import html, dcc, Input, Output, State, dash_table
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import os
import base64
import io

from src.parse_logs import parse_log_file
from src.features import compute_features
from src.train_detect import train_and_detect, generate_report
from src.visualize import plot_top_scores, plot_requests_vs_4xx

# Initialize the Dash app
app = dash.Dash(__name__)

app.layout = html.Div([
    html.H1('SOC Log Anomaly Detection Dashboard'),
    dcc.Upload(
        id='upload-log',
        children=html.Div(['Drag and Drop or Click to Upload Apache Log File']),
        style={
            'width': '100%',
            'height': '60px',
            'lineHeight': '60px',
            'borderWidth': '1px',
            'borderStyle': 'dashed',
            'borderRadius': '5px',
            'textAlign': 'center',
            'margin': '10px'
        },
        multiple=False
    ),
    html.Button('Run Analysis', id='run-analysis', n_clicks=0),
    html.Div(id='analysis-status'),
    html.H2('Top Anomalous IPs'),
    dcc.Graph(id='anomaly-plot'),
    html.H2('Requests vs 4xx Errors'),
    dcc.Graph(id='scatter-plot'),
    html.H2('Anomalies Table'),
    dash_table.DataTable(
        id='anomalies-table',
        page_size=20,
        style_table={'overflowX': 'auto'},
        style_cell={'textAlign': 'left', 'minWidth': '150px', 'width': '150px', 'maxWidth': '350px'},
    ),
    html.H2('Report'),
    html.Pre(id='report-text')
])

def parse_contents(contents, filename):
    content_type, content_string = contents.split(',')
    decoded = base64.b64decode(content_string)
    return decoded.decode('utf-8')

@app.callback(
    [Output('analysis-status', 'children'),
     Output('anomaly-plot', 'figure'),
     Output('scatter-plot', 'figure'),
     Output('anomalies-table', 'data'),
     Output('anomalies-table', 'columns'),
     Output('report-text', 'children')],
    [Input('run-analysis', 'n_clicks')],
    [State('upload-log', 'contents'),
     State('upload-log', 'filename')]
)
def run_analysis(n_clicks, contents, filename):
    if n_clicks == 0:
        return '', {}, {}, [], [], ''

    try:
        # Ensure directories
        os.makedirs('data', exist_ok=True)
        os.makedirs('outputs', exist_ok=True)

        if contents is not None:
            # Use uploaded file
            log_content = parse_contents(contents, filename)
            log_path = os.path.join('data', 'uploaded_access.log')
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write(log_content)
        elif os.path.exists(os.path.join('data', 'apache.log')):
            # Use Apache log file if present
            log_path = os.path.join('data', 'apache.log')
        else:
            # Use default sample
            log_path = os.path.join('data', 'sample_access.log')

        parsed_csv = os.path.join('data', 'logs.csv')
        anomalies_csv = os.path.join('outputs', 'anomalies.csv')
        report_txt = os.path.join('outputs', 'report.txt')

        # Parse logs
        df = parse_log_file(log_path)
        df.to_csv(parsed_csv, index=False)

        # Compute features
        features = compute_features(df)

        # Train and detect
        results = train_and_detect(features)
        results.to_csv(anomalies_csv, index=False)

        # Generate report
        generate_report(results, report_txt)

        # Create plots with Plotly
        # Top scores bar chart
        top_n = 20
        top_data = results.head(top_n)
        fig_bar = px.bar(top_data, x='anomaly_score', y='ip', orientation='h',
                         title='Top Anomalous IPs',
                         labels={'anomaly_score': 'Anomaly Score (lower = more anomalous)'})
        fig_bar.update_yaxes(autorange="reversed")

        # Scatter plot
        fig_scatter = px.scatter(results, x='requests', y='4xx_count', color='is_anomaly',
                                 title='Requests vs 4xx Errors',
                                 color_continuous_scale='RdBu')

        # Table data
        table_data = results.head(50).to_dict('records')
        columns = [{"name": i, "id": i} for i in results.columns]

        # Report text
        with open(report_txt, 'r') as f:
            report = f.read()

        status = f'Analysis completed successfully! Processed {len(df)} log entries.'

        return status, fig_bar, fig_scatter, table_data, columns, report

    except Exception as e:
        return f'Error: {str(e)}', {}, {}, [], [], ''

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8050)