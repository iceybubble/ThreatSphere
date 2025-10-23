import win32evtlog
import requests
import time
import os
from pymongo import MongoClient

# ---------------------------
# Configuration
# ---------------------------
BACKEND = "http://127.0.0.1:5000/upload"  # Replace with your backend host
API_KEY = "ca2dc42dd9cfa70355d1dfd62e0d9d4287b22b2230e924524e473e8cd046cbef"
STATE_FILE = r"D:\ThreatSphere\backend\collectors\last_record_id.txt"

INTERVAL = 5  # seconds between checks
LOG_TYPE = "Microsoft-Windows-Sysmon/Operational"

# MongoDB configuration
MONGO_URI = "mongodb://localhost:27017/"  # Replace if MongoDB is on another host
DB_NAME = "threatsphere"
COLLECTION_NAME = "sandbox_logs"

# ---------------------------
# Setup MongoDB
# ---------------------------
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    client.server_info()  # trigger connection exception if cannot connect
    print("[INFO] Connected to MongoDB")
except Exception as e:
    print(f"[WARN] Cannot connect to MongoDB: {e}")
    collection = None

# ---------------------------
# Load last processed RecordID
# ---------------------------
if os.path.exists(STATE_FILE):
    with open(STATE_FILE, "r") as f:
        last_record_id = int(f.read().strip())
else:
    last_record_id = 0

print("[INFO] Starting Sysmon collector...")
print(f"[INFO] Last processed RecordID = {last_record_id}")

# ---------------------------
# Main loop
# ---------------------------
while True:
    try:
        hand = win32evtlog.OpenEventLog("localhost", LOG_TYPE)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand, flags, 0)

        new_events = []

        for event in events:
            if event.RecordNumber <= last_record_id:
                continue  # skip old events

            event_data = {
                "event_id": event.EventID,
                "record_id": event.RecordNumber,
                "time": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                "details": event.StringInserts if event.StringInserts else []
            }
            new_events.append(event_data)

        if new_events:
            # ---------------------------
            # Batch insert into MongoDB
            # ---------------------------
            if collection:
                try:
                    collection.insert_many(new_events)
                    print(f"[INFO] Saved {len(new_events)} events to MongoDB")
                except Exception as e:
                    print(f"[WARN] Failed to save to MongoDB: {e}")

            # ---------------------------
            # Send batch to backend
            # ---------------------------
            try:
                headers = {"X-API-KEY": API_KEY}
                response = requests.post(BACKEND, headers=headers, json=new_events, timeout=10)
                if response.status_code == 200:
                    print(f"[INFO] Uploaded {len(new_events)} events -> Status: {response.json()}")
                else:
                    print(f"[WARN] Backend responded with status {response.status_code}")
            except Exception as e:
                print(f"[ERROR] Failed to upload: {e}")

            # ---------------------------
            # Update last_record_id
            # ---------------------------
            last_record_id = max(event["record_id"] for event in new_events)
            with open(STATE_FILE, "w") as f:
                f.write(str(last_record_id))

        else:
            print("[INFO] No new events since last upload.")

    except Exception as e:
        print(f"[ERROR] Collector error: {e}")

    time.sleep(INTERVAL)
