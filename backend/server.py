import os
import logging
import json
import re
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson.objectid import ObjectId
from config import MONGO_URI, DB_NAME, LOG_FILE, PORT, API_KEY

# -------------------------------
# Flask app setup
# -------------------------------
app = Flask(__name__)
CORS(app)  # allow cross-origin requests

# -------------------------------
# JSON Logging Helper
# -------------------------------
log_pattern = re.compile(r'(?P<timestamp>[\d\-\s:,]+) (?P<level>[A-Z]+) (?P<message>.*)')

def log_to_json(line):
    match = log_pattern.match(line)
    if match:
        log_json = {
            "timestamp": match.group("timestamp").replace(" ", "T") + "Z",
            "level": match.group("level"),
            "message": match.group("message").strip()
        }
        print(json.dumps(log_json))
    else:
        print(json.dumps({"raw": line.strip()}))

class JsonLogHandler(logging.StreamHandler):
    def emit(self, record):
        log_entry = self.format(record)
        log_to_json(log_entry)

# -------------------------------
# Logging setup
# -------------------------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger()
logger.addHandler(JsonLogHandler())  # add JSON output to console

# -------------------------------
# MongoDB client
# -------------------------------
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
logs_coll = db["sandbox_logs"]

# Ensure indexes
def ensure_indexes():
    logs_coll.create_index([("received_at", DESCENDING)])
    logs_coll.create_index([("level", ASCENDING)])
    logs_coll.create_index([("source", ASCENDING)])
    logs_coll.create_index([("artifacts.file_hashes", ASCENDING)])
    logging.info("Indexes ensured on sandbox_logs")

ensure_indexes()

# -------------------------------
# API key decorator
# -------------------------------
def require_api_key(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-API-KEY") or request.args.get("api_key")
        if not key or key != API_KEY:
            return jsonify({"error": "unauthorized"}), 401
        return func(*args, **kwargs)
    return wrapper

# -------------------------------
# Routes
# -------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}), 200

@app.route("/log", methods=["POST"])
@require_api_key
def receive_log():
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        logging.exception("Invalid JSON")
        return jsonify({"error": "invalid json", "detail": str(e)}), 400

    if not isinstance(payload, dict):
        return jsonify({"error": "payload must be a JSON object"}), 400

    doc = {
        "source": payload.get("source", "unknown"),
        "level": payload.get("level", "INFO"),
        "summary": payload.get("summary", "")[:200],
        "processes": payload.get("processes", []),
        "files_changed": payload.get("files_changed", []),
        "network_calls": payload.get("network_calls", []),
        "artifacts": payload.get("artifacts", {}),
        "meta": payload.get("meta", {}),
        "received_at": datetime.utcnow()
    }

    res = logs_coll.insert_one(doc)
    logging.info(f"NEW_LOG | source={doc['source']} level={doc['level']} id={res.inserted_id}")
    return jsonify({"status": "ok", "id": str(res.inserted_id)}), 201

@app.route("/logs/recent", methods=["GET"])
@require_api_key
def recent_logs():
    limit = int(request.args.get("limit", 20))
    cursor = logs_coll.find().sort("received_at", -1).limit(limit)
    out = []
    for d in cursor:
        d["_id"] = str(d["_id"])
        d["received_at"] = d["received_at"].isoformat() + "Z"
        out.append(d)
    return jsonify(out), 200

@app.route("/logs/query", methods=["GET"])
@require_api_key
def query_logs():
    q = {}
    level = request.args.get("level")
    source = request.args.get("source")
    from_ts = request.args.get("from")
    to_ts = request.args.get("to")

    if level:
        q["level"] = level
    if source:
        q["source"] = source
    if from_ts or to_ts:
        time_q = {}
        if from_ts:
            try:
                time_q["$gte"] = datetime.fromisoformat(from_ts)
            except Exception:
                return jsonify({"error": "from must be ISO datetime"}), 400
        if to_ts:
            try:
                time_q["$lte"] = datetime.fromisoformat(to_ts)
            except Exception:
                return jsonify({"error": "to must be ISO datetime"}), 400
        if time_q:
            q["received_at"] = time_q

    cursor = logs_coll.find(q).sort("received_at", -1).limit(500)
    out = []
    for d in cursor:
        d["_id"] = str(d["_id"])
        d["received_at"] = d["received_at"].isoformat() + "Z"
        out.append(d)
    return jsonify(out), 200

@app.route("/logs/<id>", methods=["GET"])
@require_api_key
def get_log(id):
    try:
        d = logs_coll.find_one({"_id": ObjectId(id)})
    except Exception:
        return jsonify({"error": "invalid id"}), 400
    if not d:
        return jsonify({"error": "not found"}), 404
    d["_id"] = str(d["_id"])
    d["received_at"] = d["received_at"].isoformat() + "Z"
    return jsonify(d), 200

@app.route("/health/full", methods=["GET"])
def full_health():
    try:
        info = client.server_info()
        return jsonify({"status": "ok", "mongodb_version": info.get("version")}), 200
    except Exception as e:
        logging.exception("DB health failed")
        return jsonify({"status": "error", "detail": str(e)}), 500

# -------------------------------
# Run server
# -------------------------------
if __name__ == "__main__":
    logging.info("Starting ThreatSphere backend on 0.0.0.0:%d", PORT)
    app.run(host="0.0.0.0", port=PORT, debug=False)
