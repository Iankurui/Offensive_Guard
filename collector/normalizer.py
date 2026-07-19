#!/usr/bin/env python3

import json
import time
import os
import requests
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ==================================================
# CONFIGURATION
# ==================================================
API_URL = "http://127.0.0.1:8000/events"

MITRE_MAP = {
    "ssh_login_failed": ("Credential Access", "T1110", "Brute Force"),
    "command_execution": ("Execution", "T1059", "Command and Scripting Interpreter"),
    "xss_blocked": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "tcp_probe": ("Reconnaissance", "T1046", "Network Service Scanning"),
    "udp_probe": ("Reconnaissance", "T1046", "Network Service Scanning"),
    "http_probe": ("Reconnaissance", "T1595", "Active Scanning")
}

file_positions = {}

# ==================================================
# BACKEND COMMUNICATION
# ==================================================
def normalize_timestamp(ts):
    if not ts:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        if "T" in ts:
            ts = ts.replace("Z", "")
            dt = datetime.fromisoformat(ts)
        else:
            dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts

def send_to_backend(event_data):
    try:
        response = requests.post(API_URL, json=event_data, timeout=5)
        if response.status_code == 200:
            print(f"[+] Sent: {event_data['event_type']} from {event_data['source_ip']}")
        else:
            print(f"[-] API ERROR {response.status_code}: {response.text}")
    except Exception as e:
        print(f"[-] BACKEND ERROR: {e}")

# ==================================================
# COWRIE HANDLER
# ==================================================
class CowrieHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith("cowrie.json"):
            self.process_file(event.src_path)

    def process_file(self, filepath):
        pos = file_positions.get(filepath, 0)
        try:
            with open(filepath, "r") as f:
                f.seek(pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue  # Safely skip empty lines
                    
                    try:
                        raw = json.loads(line)
                        if not isinstance(raw, dict):
                            continue  # Safely skip if it's not a JSON object

                        if raw.get("eventid") == "cowrie.login.failed":
                            tactic, tech_id, _ = MITRE_MAP["ssh_login_failed"]
                            normalized = {
                                "timestamp": normalize_timestamp(raw.get("timestamp")),
                                "source_ip": raw.get("src_ip"),
                                "event_type": "ssh_login_failed",
                                "severity": "Medium",
                                "asset": "cowrie",
                                "summary": f"Failed SSH login for {raw.get('username', 'unknown')}",
                                "mitre_tactic": tactic,
                                "mitre_technique_id": tech_id
                            }
                            send_to_backend(normalized)

                        elif raw.get("eventid", "").startswith("cowrie.command"):
                            tactic, tech_id, _ = MITRE_MAP["command_execution"]
                            cmd = raw.get("input") or raw.get("command") or raw.get("message") or raw.get("cmd") or ""
                            if not cmd:
                                continue

                            high_risk = ["wget", "curl", "chmod", "shadow", "passwd", "nc", "netcat", "bash", "sh", "python", "python3", "perl", "scp", "ftp", "tftp", "busybox", "chmod +x", "rm", "mv", "cat", "ls", "whoami", "uname", "id", "ifconfig", "ip ", "ping"]
                            severity = "High" if any(x in cmd.lower() for x in high_risk) else "Medium"

                            normalized = {
                                "timestamp": normalize_timestamp(raw.get("timestamp")),
                                "source_ip": raw.get("src_ip"),
                                "event_type": "command_execution",
                                "severity": severity,
                                "asset": "cowrie",
                                "summary": f"Command executed: {cmd}",
                                "mitre_tactic": tactic,
                                "mitre_technique_id": tech_id
                            }
                            send_to_backend(normalized)

                    except json.JSONDecodeError:
                        continue  # Silently skip malformed JSON
                    except Exception as e:
                        print(f"[COWRIE PARSE ERROR] {e}")

                file_positions[filepath] = f.tell()
        except Exception as e:
            print(f"[COWRIE ERROR] {e}")

# ==================================================
# CUSTOM HONEYPOT HANDLER
# ==================================================
class CustomHoneypotHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith("custom_honeypot.log"):
            self.process_file(event.src_path)

    def process_file(self, filepath):
        pos = file_positions.get(filepath, 0)
        try:
            with open(filepath, "r") as f:
                f.seek(pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                        if not isinstance(raw, dict):
                            continue
                            
                        src_ip = raw.get("src_ip")
                        port = raw.get("dst_port")
                        proto = raw.get("protocol", "").lower()
                        event_type = f"{proto}_probe"
                        tactic, tech_id, _ = MITRE_MAP.get(event_type, ("Reconnaissance", "T1046", "Network Service Scanning"))

                        normalized = {
                            "timestamp": normalize_timestamp(raw.get("timestamp")),
                            "source_ip": src_ip,
                            "event_type": event_type,
                            "severity": "Low",
                            "asset": f"custom_{proto}_{port}",
                            "summary": f"{proto.upper()} probe against port {port}",
                            "mitre_tactic": tactic,
                            "mitre_technique_id": tech_id
                        }
                        send_to_backend(normalized)
                    except json.JSONDecodeError:
                        continue
                    except Exception:
                        continue
                file_positions[filepath] = f.tell()
        except Exception as e:
            print(f"[CUSTOM ERROR] {e}")

# ==================================================
# XSS HANDLER
# ==================================================
class XSSHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith("xss_blocks.log"):
            self.process_file(event.src_path)

    def process_file(self, filepath):
        pos = file_positions.get(filepath, 0)
        try:
            with open(filepath, "r") as f:
                f.seek(pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                        if not isinstance(raw, dict):
                            continue
                            
                        tactic, tech_id, _ = MITRE_MAP["xss_blocked"]
                        normalized = {
                            "timestamp": normalize_timestamp(raw.get("timestamp")),
                            "source_ip": raw.get("src_ip"),
                            "event_type": "xss_blocked",
                            "severity": "High",
                            "asset": "http_decoy",
                            "summary": f"XSS blocked: {raw.get('payload','')[:80]}",
                            "mitre_tactic": tactic,
                            "mitre_technique_id": tech_id
                        }
                        send_to_backend(normalized)
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        print(f"[XSS ERROR] {e}")
                file_positions[filepath] = f.tell()
        except Exception as e:
            print(f"[XSS FILE ERROR] {e}")

# ==================================================
# MAIN
# ==================================================
if __name__ == "__main__":
    cowrie_log_dir = os.path.expanduser("~/cowrie/var/log/cowrie")
    custom_log_dir = os.path.expanduser("~/offensive-guard")

    observer = Observer()
    observer.schedule(CowrieHandler(), path=cowrie_log_dir, recursive=False)
    observer.schedule(CustomHoneypotHandler(), path=custom_log_dir, recursive=False)
    observer.schedule(XSSHandler(), path=custom_log_dir, recursive=False)

    startup_files = [
        os.path.expanduser("~/cowrie/var/log/cowrie/cowrie.json"),
        os.path.expanduser("~/offensive-guard/custom_honeypot.log"),
        os.path.expanduser("~/offensive-guard/xss_blocks.log")
    ]

    for path in startup_files:
        if os.path.exists(path):
            file_positions[path] = os.path.getsize(path)

    observer.start()
    print("[*] Offensive Guard Normalizer Started")
    print(f"[*] Watching: {cowrie_log_dir}")
    print(f"[*] Watching: {custom_log_dir}")
    print(f"[*] Sending events to: {API_URL}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
