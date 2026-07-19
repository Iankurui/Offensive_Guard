#!/usr/bin/env python3
"""
Custom TCP/UDP honeypot listener for Offensive Guard.
Logs all connection attempts in JSON format.
"""
import socket
import threading
import json
import datetime
import os
import time

# ========== CONFIGURATION ==========
TCP_PORTS = [445, 3389, 22, 80, 443, 8080, 8443, 3306, 5432, 6379]
UDP_PORTS = [53, 123, 161, 500, 4500]

LOG_FILE = os.path.expanduser("~/offensive-guard/custom_honeypot.log")  # Fixed path
# ===================================

def ensure_log_dir():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def log_event(data):
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(data) + "\n")

def tcp_listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(5)
    print(f"[TCP] Listening on port {port}")
    while True:
        conn, addr = s.accept()
        data = conn.recv(1024)
        conn.close()
        log_entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "src_ip": addr[0],
            "src_port": addr[1],
            "dst_port": port,
            "protocol": "tcp",
            "data": data.hex() if data else ""
        }
        log_event(log_entry)
        print(f"[TCP] Connection from {addr[0]}:{addr[1]} to port {port}")

def udp_listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', port))
    print(f"[UDP] Listening on port {port}")
    while True:
        data, addr = s.recvfrom(1024)
        log_entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "src_ip": addr[0],
            "src_port": addr[1],
            "dst_port": port,
            "protocol": "udp",
            "data": data.hex() if data else ""
        }
        log_event(log_entry)
        print(f"[UDP] Packet from {addr[0]}:{addr[1]} to port {port}")

if __name__ == "__main__":
    ensure_log_dir()
    # Start TCP threads
    for port in TCP_PORTS:
        t = threading.Thread(target=tcp_listener, args=(port,), daemon=True)
        t.start()
    # Start UDP threads
    for port in UDP_PORTS:
        t = threading.Thread(target=udp_listener, args=(port,), daemon=True)
        t.start()
    print(f"Custom honeypot listeners started. Logging to {LOG_FILE}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down...")
