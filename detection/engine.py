#!/usr/bin/env python3
import sqlite3
import time
import subprocess
import os

DB_PATH = "/home/iann/offensive-guard/events.db"

def check_bruteforce():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Count failed logins per IP, not yet high severity
    cur.execute("""
        SELECT source_ip, COUNT(*) as cnt
        FROM events
        WHERE event_type = 'ssh_login_failed' AND severity != 'High'
        GROUP BY source_ip
        HAVING cnt >= 5
    """)
    rows = cur.fetchall()
    for ip, cnt in rows:
        # Update severity to High
        cur.execute("UPDATE events SET severity = 'High' WHERE source_ip = ?", (ip,))
        conn.commit()
        # Block IP using iptables
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        print(f"[!] Blocked {ip} due to {cnt} failed logins")
    conn.close()

def check_mitre_high_risk_commands():
    """Optionally raise severity for certain MITRE techniques (e.g., T1105)."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Look for command_execution events that contain wget or curl (T1105)
    cur.execute("""
        SELECT id, source_ip, summary
        FROM events
        WHERE event_type = 'command_execution' AND severity != 'High'
          AND (summary LIKE '%wget%' OR summary LIKE '%curl%')
    """)
    rows = cur.fetchall()
    for eid, ip, summary in rows:
        cur.execute("UPDATE events SET severity = 'High' WHERE id = ?", (eid,))
        # Optionally block IP
        # subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        print(f"[!] High risk command from {ip}: {summary[:80]}")
    conn.commit()
    conn.close()

if __name__ == "__main__":
    while True:
        check_bruteforce()
        check_mitre_high_risk_commands()
        time.sleep(10)
