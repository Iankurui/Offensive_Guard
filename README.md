# Offensive Guard

An Offensive Security-Driven Active Defense Platform integrating deception technology, honeypots, automated detection, incident response, and digital evidence preservation.

## Overview

Offensive Guard is a cybersecurity platform developed as a final-year project for the Bachelor of Science in Computer Security and Forensics.

Instead of relying solely on passive monitoring, the system deploys deception mechanisms to attract attackers, collect high-fidelity attack intelligence, and automatically respond to malicious activities.

## Features

- SSH Honeypot (Cowrie)
- HTTP Decoy Web Server
- XSS Attack Detection
- Command Execution Monitoring
- Network Probe Detection (TCP/UDP/HTTP)
- Real-time Event Normalization
- MITRE ATT&CK Mapping
- Automated Incident Response
- Evidence Collection
- FastAPI Backend
- Interactive Dashboard
- SQLite Event Storage

## System Architecture

```
Attacker
    │
    ▼
+------------------+
| Deception Layer  |
| Cowrie + HTTP    |
+------------------+
          │
          ▼
+------------------+
| Log Normalizer   |
+------------------+
          │
          ▼
+------------------+
| Detection Engine |
+------------------+
          │
          ▼
+------------------+
| FastAPI Backend  |
+------------------+
          │
          ▼
+------------------+
| Dashboard        |
+------------------+
```

## Technologies Used

- Python
- FastAPI
- Flask
- Cowrie Honeypot
- SQLite
- Watchdog
- Linux (Kali)
- Windows
- MITRE ATT&CK Framework

## Project Structure

```
offensive-guard/
│
├── collector/
├── dashboard/
├── detection/
├── http-decoy/
├── response/
├── evidence/
├── docs/
├── screenshots/
└── README.md
```

## Demonstrated Attack Scenarios

- SSH Login Attempts
- Command Execution
- XSS Injection
- TCP Reconnaissance
- UDP Reconnaissance
- HTTP Scanning

## Installation

Clone the repository

```bash
git clone https://github.com/A1shiteru/Offensive_Guard.git
cd Offensive_Guard
```

Install dependencies

```bash
pip install -r requirements.txt
```

## Running the Project

Start Cowrie

```bash
cd ~/cowrie
source cowrie-env/bin/activate
cowrie start
```

Start the HTTP Decoy

```bash
cd http-decoy
python app.py
```

Start the Log Normalizer

```bash
python collector/normalizer.py
```

Start the Detection Engine

```bash
sudo python detection/engine.py
```

Start FastAPI

```bash
python dashboard/app.py
```

## Research Objectives

- Deploy deception technologies to engage attackers.
- Detect attacks in real time.
- Automate incident response.
- Preserve forensic evidence.
- Improve attack visibility using honeypots.

## Future Improvements

- Machine Learning-based anomaly detection
- Docker deployment
- SIEM integration
- Email/SMS alerts
- Threat Intelligence feeds
- Multi-honeypot support

