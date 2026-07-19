#!/usr/bin/env python3
"""
Offensive Guard – HTTP Decoy with XSS Detection
"""
from flask import Flask, request
import json
import datetime
import os
import re

app = Flask(__name__)

# Log file paths
NORMAL_LOG = os.path.expanduser("~/offensive-guard/http_decoy.log")
XSS_LOG = os.path.expanduser("~/offensive-guard/xss_blocks.log")

# Ensure log directory exists
os.makedirs(os.path.dirname(NORMAL_LOG), exist_ok=True)
os.makedirs(os.path.dirname(XSS_LOG), exist_ok=True)

def is_xss_attack(data):
    """Check if a string contains XSS patterns."""
    if not isinstance(data, str):
        return False
    patterns = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<img.*?src\s*=\s*[\"']javascript:",
        r"<iframe.*?src\s*=\s*[\"']javascript:",
        r"<body.*?onload\s*=",
        r"<input.*?on\w+\s*=",
        r"<svg.*?onload\s*=",
        r"alert\s*\(",
        r"prompt\s*\(",
        r"confirm\s*\(",
        r"document\.cookie",
        r"window\.location",
        r"eval\s*\(",
    ]
    for pattern in patterns:
        if re.search(pattern, data, re.IGNORECASE | re.DOTALL):
            return True
    return False

def log_normal_event():
    """Log normal HTTP request to http_decoy.log."""
    data = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "src_ip": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get('User-Agent', '')
    }
    with open(NORMAL_LOG, 'a') as f:
        f.write(json.dumps(data) + "\n")

from datetime import datetime, timezone,timedelta

def log_xss_block(src_ip, path, payload):

    nairobi_tz = timezone(timedelta(hours=3))
    timestamp = datetime.now(nairobi_tz).strftime("%Y-%m-%d %H:%M:%S")

    entry = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "attack_type": "XSS",
        "path": path,
        "payload": payload,
        "blocked": True
    }

    with open(XSS_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

@app.before_request
def block_xss():
    """Inspect all incoming requests for XSS patterns."""
    # Collect all data from the request
    data_to_check = []
    # Path
    data_to_check.append(request.path)
    # Query parameters (GET)
    for value in request.args.values():
        data_to_check.append(value)
    # Form data (POST)
    for value in request.form.values():
        data_to_check.append(value)
    # Raw data (e.g., JSON, XML)
    raw_data = request.get_data(as_text=True)
    if raw_data:
        data_to_check.append(raw_data)

    # Scan each piece of data
    for item in data_to_check:
        if is_xss_attack(item):
            log_xss_block(request.remote_addr, request.path, item)
            return "Forbidden: XSS attack detected", 403

    # No XSS detected, continue normally
    return None

@app.route('/')
@app.route('/admin')
@app.route('/wp-admin')
@app.route('/phpmyadmin')
@app.route('/cpanel')
def catch_all():
    """Log normal requests and return a fake OK response."""
    log_normal_event()
    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
