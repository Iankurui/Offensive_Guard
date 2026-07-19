from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from datetime import datetime
import uuid
import sqlite3
import subprocess
import glob
import json
import zipfile
import io
import os
import hashlib
import shutil

app = FastAPI()
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://192.168.56.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
DB_PATH = "/home/iann/offensive-guard/events.db"

class Event(BaseModel):
    timestamp: str
    source_ip: str
    event_type: str
    severity: str
    asset: str
    summary: str
    mitre_tactic: str = ""
    mitre_technique_id: str = ""

@app.post("/events")
def create_event(event: Event):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    event_id = f"evt_{uuid.uuid4().hex}"
    cur.execute("""
        INSERT INTO events (
            id, timestamp, source_ip, event_type, severity,
            asset, summary, raw_json, mitre_tactic, mitre_technique_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_id, event.timestamp, event.source_ip, event.event_type,
        event.severity, event.asset, event.summary,
        json.dumps(event.dict()), event.mitre_tactic, event.mitre_technique_id
    ))
    conn.commit()
    conn.close()
    return {"status": "ok", "id": event_id}

@app.get("/evidence/download/{pack_name}")
def download_evidence(pack_name: str):
    evidence_dir = os.path.expanduser("~/offensive-guard/evidence_packs")
    zip_path = os.path.join(evidence_dir, pack_name)
    if os.path.exists(zip_path):
        return FileResponse(zip_path, media_type='application/zip', filename=pack_name)
    return {"error": "File not found"}

@app.get("/events")
def get_events(
    search: str = None, 
    severity: str = None, 
    limit: int = 50, 
    offset: int = 0
):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    query = "SELECT * FROM events WHERE 1=1"
    params = []
    
    if search:
        query += " AND (source_ip LIKE ? OR event_type LIKE ? OR summary LIKE ?)"
        search_term = f"%{search}%"
        params.extend([search_term, search_term, search_term])
        
    if severity and severity != "All":
        query += " AND severity = ?"
        params.append(severity)
        
    # Ensure proper timestamp sorting
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]
@app.get("/events/count")
def get_events_count(search: str = None, severity: str = None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = "SELECT COUNT(*) FROM events WHERE 1=1"
    params = []
    if search:
        query += " AND (source_ip LIKE ? OR event_type LIKE ? OR summary LIKE ?)"
        search_term = f"%{search}%"
        params.extend([search_term, search_term, search_term])
    if severity and severity != "All":
        query += " AND severity = ?"
        params.append(severity)
    cur.execute(query, params)
    total = cur.fetchone()[0]
    conn.close()
    return {"total": total}

@app.get("/export")
def export_evidence(event_id: str = None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    if event_id:
        cur.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    else:
        return {"error": "No event_id provided"}
    row = cur.fetchone()
    conn.close()
    if not row:
        return {"error": "Event not found"}
    events_data = [dict(row)]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_id = event_id.replace(".", "_")
    pack_name = f"OffensiveGuard_Evidence_{safe_id}_{timestamp}"
    temp_dir = f"/tmp/{pack_name}"
    os.makedirs(temp_dir, exist_ok=True)
    json_path = os.path.join(temp_dir, "events.json")
    formatted_events = []
    for event in events_data:
        clean_event = dict(event)
        raw = clean_event.get('raw_json')
        if raw and isinstance(raw, str):
            try:
                clean_event['raw_json'] = json.loads(raw)
            except Exception:
                pass
        formatted_events.append(clean_event)
    with open(json_path, "w") as f:
        json.dump(formatted_events, f, indent=4, default=str)
    manifest_path = os.path.join(temp_dir, "manifest.txt")
    with open(manifest_path, "w") as f:
        f.write(f"Offensive Guard Forensic Evidence Pack\n")
        f.write(f"Target Event ID: {event_id}\n")
        f.write(f"Total Events: {len(formatted_events)}\n")
        f.write(f"Generated: {timestamp}\n")
    
    # Generate PDF Report for this event
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    
    pdf_path = os.path.join(temp_dir, "evidence_report.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    # Title
    elements.append(Paragraph("Offensive Guard - Forensic Evidence Report", styles['Title']))
    elements.append(Spacer(1, 12))
    
    # Event Details
    elements.append(Paragraph("Event Details", styles['Heading2']))
    elements.append(Spacer(1, 6))
    
    event = formatted_events[0]
    details_data = [
        ["Event ID:", event.get('id', 'N/A')],
        ["Timestamp:", event.get('timestamp', 'N/A')],
        ["Source IP:", event.get('source_ip', 'N/A')],
        ["Event Type:", event.get('event_type', 'N/A')],
        ["Severity:", event.get('severity', 'N/A')],
        ["Asset:", event.get('asset', 'N/A')],
        ["Summary:", event.get('summary', 'N/A')[:100] if event.get('summary') else 'N/A'],
        ["MITRE Tactic:", event.get('mitre_tactic', 'N/A')],
        ["MITRE Technique:", event.get('mitre_technique_id', 'N/A')],
    ]
    
    details_table = Table(details_data, colWidths=[150, 400])
    details_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(details_table)
    elements.append(Spacer(1, 20))
    
    # Raw JSON Data
    elements.append(Paragraph("Raw Event Data (JSON)", styles['Heading2']))
    elements.append(Spacer(1, 6))
    raw_json = event.get('raw_json', {})
    if isinstance(raw_json, dict):
        json_text = json.dumps(raw_json, indent=2, default=str)
    else:
        json_text = str(raw_json)
    # Split long JSON into paragraphs
    for line in json_text.split('\n'):
        elements.append(Paragraph(line, styles['Code']))
    
    # Build PDF
    doc.build(elements)
    
    sha256_hash = hashlib.sha256()
    with open(json_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    hash_path = os.path.join(temp_dir, "hashes.txt")
    with open(hash_path, "w") as f:
        f.write(f"events.json SHA-256: {sha256_hash.hexdigest()}\n")
    zip_path = f"/tmp/{pack_name}.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, temp_dir)
                zipf.write(file_path, arcname)
    shutil.rmtree(temp_dir)
    return FileResponse(zip_path, media_type='application/zip', filename=f"{pack_name}.zip")

@app.get("/stats")
def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM events")
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM events WHERE severity = 'High'")
    high = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM events WHERE severity = 'Medium'")
    medium = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM events WHERE severity = 'Low'")
    low = cur.fetchone()[0]
    cur.execute("SELECT DISTINCT source_ip FROM events WHERE severity = 'High'")
    blocked_ips = [row[0] for row in cur.fetchall()]
    conn.close()
    return {
        "total_events": total,
        "high_severity": high,
        "medium_severity": medium,
        "low_severity": low,
        "blocked_ips": blocked_ips
    }

@app.get("/evidence/list")
def list_evidence():
    evidence_dir = os.path.expanduser("~/offensive-guard/evidence_packs")
    if not os.path.exists(evidence_dir):
        return []
    files = glob.glob(os.path.join(evidence_dir, "*.zip"))
    packs = []
    for f in files:
        packs.append({"name": os.path.basename(f), "path": f})
    return packs

@app.get("/evidence/structure")
def evidence_structure(pack_name: str):
    base = os.path.expanduser("~/offensive-guard/evidence_packs")
    zip_path = os.path.join(base, pack_name)
    if not os.path.exists(zip_path):
        return {"error": "Pack not found"}
    with zipfile.ZipFile(zip_path, 'r') as zf:
        if "events.json" in zf.namelist():
            data = zf.read("events.json").decode("utf-8")
            return json.loads(data)
    return {"error": "No events.json found"}

@app.get("/active_scan")
def active_scan(target_ip: str):
    try:
        result = subprocess.run(["nmap", "-p-", "--open", "-T4", target_ip], capture_output=True, text=True, timeout=60)
        return {"target": target_ip, "output": result.stdout}
    except Exception as e:
        return {"error": str(e)}

@app.post("/block_ip")
def block_ip(ip: str):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        return {"status": "blocked", "ip": ip}
    except Exception as e:
        return {"error": str(e)}

@app.post("/drop_packets")
def drop_packets(ip: str):
    return block_ip(ip)

@app.post("/false_credential")
def false_credential(credential: str = None):
    log_entry = f"Fake credential used: {credential if credential else 'unknown'}"
    with open("/home/iann/offensive-guard/fake_creds.log", "a") as f:
        f.write(f"{log_entry}\n")
    return {"status": "logged", "message": log_entry}

@app.get("/report")
def generate_report():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM events")
    total = cur.fetchone()[0]
    cur.execute("SELECT DISTINCT source_ip FROM events")
    attackers = [row[0] for row in cur.fetchall()]
    conn.close()
    return {
        "total_events": total,
        "attackers": attackers,
        "ttps": ["SSH brute‑force", "Credential guessing"],
        "affected_systems": ["Cowrie SSH honeypot", "HTTP decoy"],
        "defence_methods": ["IP blocking via iptables", "Automated alerting", "Evidence packaging with SHA‑256"],
        "structured_evidence": {
            "format": "JSON + ZIP",
            "hashes": "SHA-256 per pack",
            "database": "SQLite at ~/offensive-guard/events.db"
        }
    }

@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    with open("dashboard/index.html", "r") as f:
        return f.read()

DEMO_USER = {"username": "admin", "password": "admin123"}

@app.post("/login")
async def login(request: Request):
    data = await request.json()
    user = data.get("username")
    pwd = data.get("password")
    if user == DEMO_USER["username"] and pwd == DEMO_USER["password"]:
        return {"success": True, "message": "Login successful"}
    else:
        return {"success": False, "message": "Invalid credentials"}

@app.get("/suspicious_ips")
def get_suspicious_ips():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT source_ip, COUNT(*) as count,
               MAX(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as is_high,
               MAX(CASE WHEN source_ip IN (SELECT source_ip FROM events WHERE severity = 'High') THEN 1 ELSE 0 END) as blocked
        FROM events
        GROUP BY source_ip
        ORDER BY count DESC
    """)
    rows = cur.fetchall()
    conn.close()
    result = []
    for row in rows:
        result.append({
            "ip": row[0],
            "count": row[1],
            "high": bool(row[2]),
            "blocked": bool(row[3])
        })
    return result

@app.get("/export/pdf")
def export_pdf():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT 100")
    rows = cur.fetchall()
    conn.close()
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    elements.append(Paragraph("Offensive Guard - Incident Report", styles['Title']))
    elements.append(Spacer(1, 12))
    
    data = [["Time", "Source IP", "Event Type", "Severity", "Summary"]]
    for row in rows:
        data.append([
            str(row['timestamp'])[:19],
            str(row['source_ip']),
            str(row['event_type']),
            str(row['severity']),
            str(row['summary'])[:50] if row['summary'] else ""
        ])
        
    t = Table(data, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#8b5cf6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
    ]))
    elements.append(t)
    
    doc.build(elements)
    buffer.seek(0)
    
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=OffensiveGuard_Report.pdf"}
    )

@app.post("/whitelist_ip")
def whitelist_ip(ip: str):
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
        return {"success": True, "message": f"IP {ip} whitelisted (rule removed)."}
    except Exception as e:
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
