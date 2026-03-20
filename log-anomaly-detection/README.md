# SOC Log Anomaly Detection Dashboard

This project implements a web-based Security Operations Center (SOC) dashboard for AI-based anomaly detection in Apache access logs. It parses raw logs, engineers per-IP features, trains an Isolation Forest model, and provides interactive visualizations and reports to highlight suspicious IPs.

## 🛠 What it does
1. Reads Apache access logs (common/combined-like format).
2. Converts them to a structured CSV (`data/logs.csv`).
3. Aggregates features per source IP such as request counts, error rates, suspicious path accesses, and time-based rates.
4. Applies **Isolation Forest** to score and flag anomalies.
5. Provides a web dashboard with:
   - Interactive plots of anomaly scores and patterns.
   - Data table of suspicious IPs.
   - Text report with analysis hints.
   - Outputs saved to files for further processing.

## 🚀 How to run
1. Create a virtual environment:
   ```powershell
   python -m venv venv
   ```

2. Activate it:
   - **PowerShell:** `venv\Scripts\Activate.ps1`
   - **CMD:** `venv\Scripts\activate.bat`
   - **Linux/macOS:** `source venv/bin/activate`

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the dashboard:
   ```bash
   python dashboard.py
   ```

   The dashboard will be available at `http://127.0.0.1:8050/`. Upload an Apache log file or use the default sample, then click "Run Analysis" to process the logs and view results.

Everything runs end-to-end with the included `data/sample_access.log`. The outputs directory will populate with the results.

## 📁 Files generated
- `data/logs.csv`: structured copy of the parsed access log.
- `outputs/anomalies.csv`: features and anomaly flags per IP.
- `outputs/report.txt`: summary and hints for security analysts.
- `outputs/*.png`: visualization images (legacy, dashboard uses interactive plots).

## 📝 Using real Apache logs
Replace `data/sample_access.log` with your own log file (same format). You can modify `log_path` in `dashboard.py` or add file upload functionality.

## 🔍 Interpreting anomalies
- **Anomaly score**: lower values indicate behavior diverging from the norm.
- **Flags**: `is_anomaly`=1 marks potentially malicious IPs.
- Investigate IPs with high request rates, numerous errors, or hits to suspicious paths (`wp-login`, `phpmyadmin`, `.env`, etc.).
- Use as a starting point in SIEM dashboards, IDS/IPS alerts, or manual hunts.

---

Feel free to extend the feature set, swap the model, or integrate into larger detection systems.