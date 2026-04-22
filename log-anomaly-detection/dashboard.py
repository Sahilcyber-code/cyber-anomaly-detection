import dash
from dash import html, dcc, Input, Output, State, dash_table
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import os
import base64
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from io import BytesIO

from src.parse_logs import parse_log_file
from src.features import compute_features
from src.train_detect import train_and_detect, generate_report
from src.visualize import plot_top_scores, plot_requests_vs_4xx

# Initialize the Dash app
app = dash.Dash(__name__)

app.layout = html.Div([
    html.Div([
        html.Div([
            html.H1('SOC Log Anomaly Detection Dashboard', style={'margin': '0', 'fontSize': '34px', 'fontWeight': '700'}),
            html.P(
                'Analyze Apache access logs, detect suspicious IP behavior, and export professional reports.',
                style={'margin': '10px 0 0 0', 'color': '#5a6378', 'fontSize': '16px'}
            )
        ], style={'padding': '30px 0', 'borderBottom': '1px solid #dfe3e8'}),

        html.Div([
            html.Div([
                html.H2('Upload & Analyze', style={'fontSize': '20px', 'marginBottom': '15px'}),
                dcc.Upload(
                    id='upload-log',
                    children=html.Div(['Drag and drop or click to upload Apache log file']),
                    style={
                        'width': '100%',
                        'minHeight': '70px',
                        'lineHeight': '70px',
                        'borderWidth': '1px',
                        'borderStyle': 'dashed',
                        'borderRadius': '10px',
                        'textAlign': 'center',
                        'backgroundColor': '#ffffff',
                        'borderColor': '#c3cfd9',
                        'color': '#5a6378'
                    },
                    multiple=False
                ),
                html.Div([
                    html.Button('Run Analysis', id='run-analysis', n_clicks=0, style={
                        'backgroundColor': '#2d8cff',
                        'color': '#fff',
                        'border': 'none',
                        'padding': '12px 20px',
                        'borderRadius': '8px',
                        'cursor': 'pointer',
                        'marginTop': '15px'
                    }),
                ], style={'display': 'flex', 'justifyContent': 'flex-start'}),
                html.Div(id='analysis-status', style={'marginTop': '15px', 'color': '#2c3e50'}),
                html.Div(id='alerts', style={'color': '#c0392b', 'marginTop': '10px', 'fontWeight': '700'})
            ], style={'padding': '25px', 'backgroundColor': '#ffffff', 'borderRadius': '12px', 'boxShadow': '0 2px 10px rgba(15, 23, 42, 0.06)'}),

            html.Div([
                html.H2('Filters', style={'fontSize': '20px', 'marginBottom': '15px'}),
                html.Div([
                    dcc.DatePickerRange(
                        id='date-range',
                        start_date_placeholder_text='Start Date',
                        end_date_placeholder_text='End Date',
                        display_format='YYYY-MM-DD',
                        style={'width': '100%'}
                    ),
                    dcc.Input(id='ip-start', type='text', placeholder='Start IP (e.g., 192.168.1.1)', style={
                        'width': '100%',
                        'padding': '12px 14px',
                        'borderRadius': '8px',
                        'border': '1px solid #c3cfd9',
                        'marginTop': '12px'
                    }),
                    dcc.Input(id='ip-end', type='text', placeholder='End IP (e.g., 192.168.1.255)', style={
                        'width': '100%',
                        'padding': '12px 14px',
                        'borderRadius': '8px',
                        'border': '1px solid #c3cfd9',
                        'marginTop': '12px'
                    }),
                    html.Button('Apply Filters', id='apply-filters', n_clicks=0, style={
                        'backgroundColor': '#1c7ed6',
                        'color': '#fff',
                        'border': 'none',
                        'padding': '12px 20px',
                        'borderRadius': '8px',
                        'cursor': 'pointer',
                        'marginTop': '15px'
                    })
                ], style={'display': 'grid', 'gridTemplateColumns': '1fr', 'gap': '10px'})
            ], style={'padding': '25px', 'backgroundColor': '#ffffff', 'borderRadius': '12px', 'boxShadow': '0 2px 10px rgba(15, 23, 42, 0.06)'})
        ], style={'display': 'grid', 'gridTemplateColumns': '1.6fr 1fr', 'gap': '20px', 'marginTop': '25px'}),

        html.Div([
            html.Div([
                html.H2('Top Anomalous IPs', style={'fontSize': '20px', 'marginBottom': '15px'}),
                dcc.Graph(id='anomaly-plot', config={'displayModeBar': False})
            ], style={'padding': '25px', 'backgroundColor': '#ffffff', 'borderRadius': '12px', 'boxShadow': '0 2px 10px rgba(15, 23, 42, 0.06)'}),
            html.Div([
                html.H2('Requests vs 4xx Errors', style={'fontSize': '20px', 'marginBottom': '15px'}),
                dcc.Graph(id='scatter-plot', config={'displayModeBar': False})
            ], style={'padding': '25px', 'backgroundColor': '#ffffff', 'borderRadius': '12px', 'boxShadow': '0 2px 10px rgba(15, 23, 42, 0.06)'})
        ], style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr', 'gap': '20px', 'marginTop': '25px'}),

        html.Div([
            html.Div([
                html.Div([
                    html.H2('Anomalies Table', style={'fontSize': '20px', 'marginBottom': '15px'}),
                    dash_table.DataTable(
                        id='anomalies-table',
                        page_size=20,
                        style_table={'overflowX': 'auto'},
                        style_cell={'textAlign': 'left', 'minWidth': '140px', 'width': '140px', 'maxWidth': '280px'},
                        row_selectable='single',
                        style_header={
                            'backgroundColor': '#f4f6fb',
                            'fontWeight': '700',
                            'border': 'none'
                        },
                        style_data={
                            'border': 'none',
                            'backgroundColor': '#ffffff'
                        }
                    ),
                    html.Div([
                        html.Button('View IP Details', id='view-details', n_clicks=0, style={
                            'backgroundColor': '#1c7ed6',
                            'color': '#fff',
                            'border': 'none',
                            'padding': '12px 20px',
                            'borderRadius': '8px',
                            'cursor': 'pointer'
                        })
                    ], style={'marginTop': '15px'})
                ])
            ], style={'padding': '25px', 'backgroundColor': '#ffffff', 'borderRadius': '12px', 'boxShadow': '0 2px 10px rgba(15, 23, 42, 0.06)'}),

            html.Div([
                html.H2('Report', style={'fontSize': '20px', 'marginBottom': '15px'}),
                html.Pre(id='report-text', style={'whiteSpace': 'pre-wrap', 'wordBreak': 'break-word', 'margin': '0', 'color': '#2c3e50'}),
                html.Div([
                    html.Button('Download CSV', id='download-csv', n_clicks=0, style={
                        'backgroundColor': '#2d8cff',
                        'color': '#fff',
                        'border': 'none',
                        'padding': '12px 20px',
                        'borderRadius': '8px',
                        'cursor': 'pointer',
                        'marginRight': '10px'
                    }),
                    html.Button('Download PDF Report', id='download-pdf', n_clicks=0, style={
                        'backgroundColor': '#20c997',
                        'color': '#fff',
                        'border': 'none',
                        'padding': '12px 20px',
                        'borderRadius': '8px',
                        'cursor': 'pointer'
                    })
                ], style={'marginTop': '20px'}),
                dcc.Download(id='download-component')
            ], style={'padding': '25px', 'backgroundColor': '#ffffff', 'borderRadius': '12px', 'boxShadow': '0 2px 10px rgba(15, 23, 42, 0.06)'}),
        ], style={'display': 'grid', 'gridTemplateColumns': '1.6fr 1fr', 'gap': '20px', 'marginTop': '25px'}),

        dcc.Store(id='results-store'),
        dcc.Store(id='logs-store'),
        dcc.Store(id='filtered-store'),
        html.Div(
            id='ip-modal',
            children=[
                html.Div([
                    html.Div([
                        html.H3(id='modal-title', style={'marginTop': '0'}),
                        html.Pre(id='modal-content', style={'whiteSpace': 'pre-wrap', 'wordBreak': 'break-word', 'color': '#2c3e50'}),
                        html.Button('Close', id='close-modal', n_clicks=0, style={
                            'backgroundColor': '#6c757d',
                            'color': '#fff',
                            'border': 'none',
                            'padding': '10px 18px',
                            'borderRadius': '8px',
                            'cursor': 'pointer',
                            'marginTop': '15px'
                        })
                    ], style={
                        'backgroundColor': '#fff',
                        'padding': '24px',
                        'borderRadius': '12px',
                        'maxWidth': '700px',
                        'width': '90%',
                        'margin': '40px auto'
                    })
                ], style={
                    'position': 'fixed',
                    'top': 0,
                    'left': 0,
                    'width': '100%',
                    'height': '100%',
                    'backgroundColor': 'rgba(0, 0, 0, 0.55)',
                    'display': 'none',
                    'zIndex': 9999
                })
            ]
        )
    ], style={'maxWidth': '1200px', 'margin': '0 auto', 'padding': '30px 20px 40px 20px'}),
], style={'backgroundColor': '#eef2f7', 'minHeight': '100vh'})

def parse_contents(contents, filename):
    content_type, content_string = contents.split(',')
    decoded = base64.b64decode(content_string)
    return decoded.decode('utf-8')

@app.callback(
    [Output('analysis-status', 'children'),
     Output('results-store', 'data'),
     Output('logs-store', 'data'),
     Output('filtered-store', 'data'),
     Output('alerts', 'children')],
    [Input('run-analysis', 'n_clicks')],
    [State('upload-log', 'contents'),
     State('upload-log', 'filename')]
)
def run_analysis(n_clicks, contents, filename):
    if n_clicks == 0:
        return '', None, None, None, ''

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

        # Store data
        results_dict = results.to_dict('records')
        logs_dict = df.to_dict('records')

        # Alerts
        anomaly_count = results['is_anomaly'].sum()
        alerts = f'Alert: {anomaly_count} new anomalies detected!' if anomaly_count > 0 else ''

        status = f'Analysis completed successfully! Processed {len(df)} log entries.'

        return status, results_dict, logs_dict, results_dict, alerts

    except Exception as e:
        return f'Error: {str(e)}', None, None, None, ''

@app.callback(
    [Output('anomaly-plot', 'figure'),
     Output('scatter-plot', 'figure'),
     Output('anomalies-table', 'data'),
     Output('anomalies-table', 'columns'),
     Output('report-text', 'children')],
    [Input('filtered-store', 'data')]
)
def update_displays(data):
    if not data:
        return {}, {}, [], [], ''

    results = pd.DataFrame(data)

    top_n = 20
    top_data = results.head(top_n)
    fig_bar = px.bar(top_data, x='anomaly_score', y='ip', orientation='h',
                     title='Top Anomalous IPs',
                     labels={'anomaly_score': 'Anomaly Score (lower = more anomalous)'})
    fig_bar.update_yaxes(autorange="reversed")

    fig_scatter = px.scatter(results, x='requests', y='4xx_count', color='is_anomaly',
                             title='Requests vs 4xx Errors',
                             color_continuous_scale='RdBu')

    table_data = results.head(50).to_dict('records')
    columns = [{"name": i, "id": i} for i in results.columns]

    report = f'Total IPs: {len(results)}. Anomalies: {results["is_anomaly"].sum()}'

    return fig_bar, fig_scatter, table_data, columns, report

@app.callback(
    Output('ip-modal', 'style'),
    [Input('view-details', 'n_clicks'), Input('close-modal', 'n_clicks')],
    [State('ip-modal', 'style'), State('anomalies-table', 'selected_rows'), State('filtered-store', 'data')]
)
def toggle_modal(view_clicks, close_clicks, current_style, selected_rows, filtered_data):
    if current_style is None:
        current_style = {'display': 'none'}

    if view_clicks and selected_rows and filtered_data:
        # open modal
        return {**current_style, 'display': 'block'}
    if close_clicks:
        return {**current_style, 'display': 'none'}
    return current_style

@app.callback(
    [Output('modal-title', 'children'), Output('modal-content', 'children')],
    [Input('view-details', 'n_clicks')],
    [State('anomalies-table', 'selected_rows'), State('filtered-store', 'data'), State('logs-store', 'data')]
)
def show_ip_details(n_clicks, selected_rows, filtered_data, logs_data):
    if n_clicks == 0 or not selected_rows or not filtered_data:
        return '', ''

    results = pd.DataFrame(filtered_data)
    logs = pd.DataFrame(logs_data)

    selected_row = selected_rows[0]
    ip = results.iloc[selected_row]['ip']

    ip_logs = logs[logs['ip'] == ip]
    details = f'IP: {ip}\nTotal Requests: {len(ip_logs)}\n'
    details += ip_logs.head(10).to_string(index=False)

    return f'Details for IP: {ip}', details

@app.callback(
    Output('download-component', 'data'),
    [Input('download-csv', 'n_clicks'), Input('download-pdf', 'n_clicks')],
    [State('filtered-store', 'data')]
)
def download_data(csv_clicks, pdf_clicks, data):
    if not data:
        return None

    results = pd.DataFrame(data)
    triggered = dash.callback_context.triggered
    if not triggered:
        return None

    button_id = triggered[0]['prop_id'].split('.')[0]
    if button_id == 'download-csv':
        return dcc.send_data_frame(results.to_csv, 'anomalies_filtered.csv', index=False)

    if button_id == 'download-pdf':
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph('Anomaly Detection Report', styles['Title']))
        story.append(Spacer(1, 12))

        report_text = f'Total IPs: {len(results)}. Anomalies: {results["is_anomaly"].sum()}.'
        story.append(Paragraph(report_text, styles['Normal']))
        story.append(Spacer(1, 12))

        for _, row in results.head(10).iterrows():
            text = f"IP: {row['ip']}, Score: {row['anomaly_score']:.4f}, Requests: {row['requests']}, Errors: {row['error_count']}"
            story.append(Paragraph(text, styles['Normal']))
            story.append(Spacer(1, 6))

        doc.build(story)
        buffer.seek(0)
        return dcc.send_bytes(buffer.getvalue(), 'report.pdf')

    return None

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8050)