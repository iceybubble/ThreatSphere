import json
import os
from datetime import datetime
from pymongo import MongoClient
from config import MONGO_URI, DB_NAME

# Output file
EXPORT_DIR = os.path.join(os.getcwd(), "exports")
EXPORT_FILE = os.path.join(EXPORT_DIR, "run_recent.json")

# Ensure exports directory exists
os.makedirs(EXPORT_DIR, exist_ok=True)

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
logs_coll = db["sandbox_logs"]

# Fetch recent logs (all logs or limit if you want)
cursor = logs_coll.find().sort("received_at", -1)
logs = []

for doc in cursor:
    doc["_id"] = str(doc["_id"])
    if isinstance(doc.get("received_at"), datetime):
        doc["received_at"] = doc["received_at"].isoformat() + "Z"
    logs.append(doc)

# Save to JSON
with open(EXPORT_FILE, "w", encoding="utf-8") as f:
    json.dump(logs, f, indent=2)

print(f"Exported {len(logs)} logs to {EXPORT_FILE}")
