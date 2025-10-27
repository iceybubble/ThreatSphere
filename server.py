import os
import logging
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from pymongo import MongoClient, DESCENDING
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename
from functools import wraps

# -------------------------------
# Configuration
# -------------------------------
MONGO_URI = os.getenv("MONGO_URI")  # MongoDB Atlas connection string
DB_NAME = os.getenv("DB_NAME", "threatsphere")
API_KEY = os.getenv("API_KEY", "changeme")
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"pcap", "pcapng", "csv", "xml", "json", "txt"}
LOG_FILE = os.getenv("LOG_FILE", "server.log")

# -------------------------------
# Flask App Setup
# -------------------------------
app = Flask(__name__, template_folder="frontend")
CORS(app)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# -------------------------------
# Logging Setup
# -------------------------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger()

# -------------------------------
# MongoDB Client Setup
# -------------------------------
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
logs_coll = db["sandbox_logs"]
artifacts_coll = db["artifacts"]

# Ensure indexes exist
logs_coll.create_index([("received_at", DESCENDING)])
artifacts_coll.create_index([("uploaded_at", DESCENDING)])
logging.info("Indexes ensured on sandbox_logs & artifacts")

# -------------------------------
# Helper Functions
# -------------------------------
def require_api_key(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        req_key = request.headers.get("X-API-KEY") or request.args.get("api_key")
        if not API_KEY or req_key != API_KEY:
            return jsonify({"error": "unauthorized"}), 401
        return func(*args, **kwargs)
    return wrapper


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# -------------------------------
# Routes
# -------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}), 200


@app.route("/logs/recent", methods=["GET"])
@require_api_key
def recent_logs():
    limit = min(int(request.args.get("limit", 50)), 100)
    cursor = logs_coll.find({}, {"processes": 0, "files_changed": 0, "network_calls": 0}).sort("received_at", -1).limit(limit)
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


@app.route("/log", methods=["POST"])
@require_api_key
def receive_log():
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        logging.exception("Invalid JSON")
        return jsonify({"error": "invalid json", "detail": str(e)}), 400

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
        return jsonify({"status": "ok", "filename": filename}), 201

    return jsonify({"error": "invalid file type"}), 400


@app.route("/health/full", methods=["GET"])
def full_health():
    try:
        info = client.server_info()
        return jsonify({"status": "ok", "mongodb_version": info.get("version")}), 200
    except Exception as e:
        logging.exception("DB health failed")
        return jsonify({"status": "error", "detail": str(e)}), 500


@app.route("/")
def home():
    return render_template("index.html")  # serves your frontend page


# -------------------------------
# Run the App
# -------------------------------
if __name__ == "__main__":
    PORT = int(os.getenv("PORT", 5000))
    logging.info(f"Starting ThreatSphere backend on http://127.0.0.1:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=True)
