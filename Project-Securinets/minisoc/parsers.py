import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# SSH syslog regex: e.g. Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2
SSH_LOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)

# IPv4 address pattern
IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

# Apache Combined log regex:
# 83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /presentations/... HTTP/1.1" 200 203023 "referer" "user-agent"
HTTP_COMBINED_PATTERN = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<resource>\S+)(?:\s+(?P<proto>[^"]+))?"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_ssh_timestamp(month_str: str, day_str: str, time_str: str, default_year: int = 2026) -> str:
    """
    Converts SSH syslog timestamp (e.g. 'Dec 10 06:55:46') to UTC ISO 8601.
    Assumes default_year (2026) and UTC when year/timezone are absent in the log.
    """
    month = MONTHS.get(month_str, 1)
    day = int(day_str)
    hour, minute, second = map(int, time_str.split(":"))
    dt = datetime(default_year, month, day, hour, minute, second, tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ssh_line(raw_line: str, default_year: int = 2026) -> Optional[Dict[str, Any]]:
    """Parses a single SSH log line into a normalized event dictionary, or returns None if invalid."""
    line = raw_line.strip()
    if not line:
        return None

    match = SSH_LOG_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()
    timestamp_utc = parse_ssh_timestamp(data["month"], data["day"], data["time"], default_year)
    message = data["message"]

    ip_match = IP_PATTERN.search(message)
    src_ip = ip_match.group(0) if ip_match else None

    msg_lower = message.lower()
    user = None
    if "invalid user" in msg_lower:
        user_match = re.search(r"invalid user\s+(\S+)", message, re.IGNORECASE)
        user = user_match.group(1) if user_match else "unknown"
        action = "Failed Password (Invalid User)"
    elif "failed password" in msg_lower:
        user_match = re.search(r"for\s+(\S+)\s+from", message, re.IGNORECASE)
        user = user_match.group(1) if user_match else "unknown"
        action = "Failed Password"
    elif "accepted password" in msg_lower or "accepted publickey" in msg_lower:
        user_match = re.search(r"for\s+(\S+)\s+from", message, re.IGNORECASE)
        user = user_match.group(1) if user_match else "unknown"
        action = "Accepted Connection"
    elif "connection closed" in msg_lower:
        action = "Connection Closed"
    else:
        action = "SSH Activity"

    return {
        "timestamp_utc": timestamp_utc,
        "source_type": "ssh",
        "src_ip": src_ip,
        "user_or_method": user,
        "action_or_resource": action,
        "status_code": None,
        "raw_log": line,
    }


def parse_http_timestamp(ts_str: str) -> str:
    """Converts Apache timestamp (e.g. '17/May/2015:10:05:03 +0000') to UTC ISO 8601."""
    dt = datetime.strptime(ts_str.strip(), "%d/%b/%Y:%H:%M:%S %z")
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_http_line(raw_line: str) -> Optional[Dict[str, Any]]:
    """Parses a single Apache Combined log line into a normalized event dictionary, or returns None if invalid."""
    line = raw_line.strip()
    if not line:
        return None

    match = HTTP_COMBINED_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()
    return {
        "timestamp_utc": parse_http_timestamp(data["ts"]),
        "source_type": "http",
        "src_ip": data["ip"],
        "user_or_method": data["method"],
        "action_or_resource": data["resource"],
        "status_code": int(data["status"]),
        "raw_log": line,
    }


def parse_log_line(raw_line: str, source_type: str, default_year: int = 2026) -> Optional[Dict[str, Any]]:
    """Dispatches a raw log line to the appropriate parser ('ssh' or 'http')."""
    kind = source_type.lower().strip()
    if kind == "ssh":
        return parse_ssh_line(raw_line, default_year=default_year)
    if kind == "http":
        return parse_http_line(raw_line)
    raise ValueError(f"Unsupported source_type: {source_type}")


if __name__ == "__main__":
    ssh_sample = "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2"
    http_sample = '83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1" 200 203023 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0"'

    print("SSH test:", parse_log_line(ssh_sample, "ssh"))
    print("HTTP test:", parse_log_line(http_sample, "http"))