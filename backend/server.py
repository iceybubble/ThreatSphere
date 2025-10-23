import os
import logging
import json
import re
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename
from config import MONGO_URI, DB_NAME, LOG_FILE, API_KEY

# -------------------------------
# Flask app setup
# -------------------------------
app = Flask(__name__)
CORS(app)

# -------------------------------
# Upload directory setup
# -------------------------------
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"pcap", "pcapng", "csv", "xml", "json", "txt"}

# -------------------------------
# JSON Logging Helper
# -------------------------------
log_pattern = re.compile(r"(?P<timestamp>[\d\-\s:,]+) (?P<level>[A-Z]+) (?P<message>.*)")

def log_to_json(line):
    match = log_pattern.match(line)
    if match:
        log_json = {
            "timestamp": match.group("timestamp").replace(" ", "T") + "Z",
            "level": match.group("level"),
            "message": match.group("message").strip(),
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
LOG_FILE = LOG_FILE or "server.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger()
logger.addHandler(JsonLogHandler())

# -------------------------------
# MongoDB client
# -------------------------------
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
logs_coll = db["sandbox_logs"]
artifacts_coll = db["artifacts"]

# Ensure indexes
def ensure_indexes():
    logs_coll.create_index([("received_at", DESCENDING)])
    logs_coll.create_index([("level", ASCENDING)])
    logs_coll.create_index([("source", ASCENDING)])
    artifacts_coll.create_index([("uploaded_at", DESCENDING)])
    logging.info("Indexes ensured on sandbox_logs & artifacts")

ensure_indexes()

# -------------------------------
# API key decorator
# -------------------------------
def require_api_key(func):
    from functools import wraps
    key = API_KEY or os.getenv("API_KEY")
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        req_key = request.headers.get("X-API-KEY") or request.args.get("api_key")
        if not key or req_key != key:
            return jsonify({"error": "unauthorized"}), 401
        return func(*args, **kwargs)
    return wrapper

# -------------------------------
# Helper for upload
# -------------------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

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
        "received_at": datetime.utcnow(),
    }

    res = logs_coll.insert_one(doc)
    logging.info(f"NEW_LOG | source={doc['source']} level={doc['level']} id={res.inserted_id}")
    return jsonify({"status": "ok", "id": str(res.inserted_id)}), 201

@app.route("/upload", methods=["POST"])
@require_api_key
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "no file part"}), 400
    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "no selected file"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(save_path)

        # --- NEW: save JSON content to sandbox_logs if file is JSON ---
        try:
            if filename.lower().endswith(".json"):
                with open(save_path) as f:
                    capture_data = json.load(f)
                log_doc = {
                    "source": request.form.get("source", "unknown"),
                    "note": request.form.get("note", ""),
                    "filename": filename,
                    "size": os.path.getsize(save_path),
                    "capture": capture_data,
                    "received_at": datetime.utcnow(),
                    "level": "INFO",
                }
                logs_coll.insert_one(log_doc)
                logging.info(f"NEW_LOG | {filename} uploaded to sandbox_logs from {log_doc['source']}")
            else:
                # Non-JSON files go to artifacts
                artifact_doc = {
                    "filename": filename,
                    "path": save_path,
                    "source": request.form.get("source", "unknown"),
                    "note": request.form.get("note", ""),
                    "size": os.path.getsize(save_path),
                    "uploaded_at": datetime.utcnow(),
                }
                artifacts_coll.insert_one(artifact_doc)
                logging.info(f"NEW_ARTIFACT | {filename} uploaded from {artifact_doc['source']}")
        except Exception as e:
            logging.exception(f"Failed to insert {filename}: {e}")
            return jsonify({"error": "failed to process file", "detail": str(e)}), 500

        return jsonify({"status": "ok", "filename": filename}), 201

    return jsonify({"error": "invalid file type"}), 400

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

if __name__ == "__main__":
    PORT = int(os.getenv("PORT", 5000))
    logging.info(f"Starting ThreatSphere backend on 0.0.0.0:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
