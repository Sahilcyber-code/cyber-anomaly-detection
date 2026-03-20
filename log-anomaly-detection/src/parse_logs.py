import re
from datetime import datetime
import pandas as pd
from typing import List

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^\"]+" (?P<status>\d{3}) (?P<bytes>\d+|-)'  # noqa: E501
)


def parse_line(line: str):
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    data = match.groupdict()
    # convert types
    try:
        # parse timestamp with timezone
        data['timestamp'] = datetime.strptime(data['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
    except Exception:
        # fallback to pandas
        data['timestamp'] = pd.to_datetime(data['timestamp'], utc=True)
    data['status'] = int(data['status'])
    data['bytes'] = int(data['bytes']) if data['bytes'].isdigit() else 0
    return data


def parse_log_file(input_path: str) -> pd.DataFrame:
    """Read an Apache access log and return structured DataFrame.

    Lines that cannot be parsed are skipped.
    Raises a ValueError if no lines are successfully parsed.
    """
    records: List[dict] = []
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parsed = parse_line(line)
            if parsed is None:
                continue
            records.append(parsed)
    if not records:
        raise ValueError(f"No valid log lines parsed from {input_path}")
    df = pd.DataFrame(records)
    return df
