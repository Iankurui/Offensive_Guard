import sqlite3
import json
import hashlib
import zipfile
import datetime
import os

DB_PATH = "/home/iann/offensive-guard/events.db"

def export_evidence(ip_filter=None, output_dir=os.path.expanduser("~/offensive-guard/evidence_packs")):
    os.makedirs(output_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if ip_filter:
        cur.execute("SELECT * FROM events WHERE source_ip = ?", (ip_filter,))
    else:
        cur.execute("SELECT * FROM events")
    events = cur.fetchall()
    conn.close()

    pack_id = f"pack_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    zip_path = os.path.join(output_dir, f"{pack_id}.zip")
    manifest = {"pack_id": pack_id, "created": datetime.datetime.utcnow().isoformat(), "events": []}

    with zipfile.ZipFile(zip_path, 'w') as zf:
        events_json = [{"id": e[0], "timestamp": e[1], "source_ip": e[2], "event_type": e[3], "severity": e[4], "asset": e[5], "summary": e[6]} for e in events]
        zf.writestr("events.json", json.dumps(events_json, indent=2))
        with open(zip_path, 'rb') as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        manifest["zip_sha256"] = sha256
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    print(f"Evidence pack created: {zip_path} (SHA256: {sha256})")

if __name__ == "__main__":
    import sys
    ip = sys.argv[1] if len(sys.argv) > 1 else None
    export_evidence(ip)
