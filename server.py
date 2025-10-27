import os
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from pymongo import MongoClient, DESCENDING
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename
from functools import wraps
from dotenv import load_dotenv

# -------------------------------
# Load environment variables
# -------------------------------
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/threatsphere")
DB_NAME = os.getenv("DB_NAME", "threatsphere")
API_KEY = os.getenv("API_KEY", "changeme")
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
LOG_FILE = os.getenv("LOG_FILE", "server.log")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------------------------
# Flask App Setup
# -------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
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
# MongoDB Setup
# -------------------------------
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
logs_coll = db["sandbox_logs"]
artifacts_coll = db["artifacts"]

logs_coll.create_index([("received_at", DESCENDING)])
artifacts_coll.create_index([("uploaded_at", DESCENDING)])

# -------------------------------
# Helpers
# -------------------------------
def require_api_key(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        req_key = request.headers.get("X-API-KEY") or request.args.get("api_key")
        if not API_KEY or req_key != API_KEY:
            logging.warning("Unauthorized access attempt.")
            return jsonify({"error": "unauthorized"}), 401
        return func(*args, **kwargs)
    return wrapper


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"pcap", "pcapng", "csv", "xml", "json", "txt"}

# -------------------------------
# Routes
# -------------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}), 200


@app.route("/logs/recent")
@require_api_key
def get_recent_logs():
    cursor = logs_coll.find({}, {"_id": 0}).sort("received_at", -1).limit(50)
    logs = []
    for log in cursor:
        logs.append({
            "received_at": log.get("received_at", "").isoformat() + "Z" if log.get("received_at") else "--",
            "category": log.get("category", log.get("source", "uncategorized")),
            "summary": log.get("summary", "No summary"),
            "level": log.get("level", "INFO"),
        })
    return jsonify(logs), 200


@app.route("/categories")
@require_api_key
def get_categories():
    pipeline = [
        {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    categories = list(logs_coll.aggregate(pipeline))
    formatted = {c["_id"]: c["count"] for c in categories if c["_id"]}
    return jsonify(formatted), 200


@app.route("/malware")
@require_api_key
def get_malware():
    cursor = artifacts_coll.find({}, {"_id": 0, "filename": 1, "uploaded_at": 1, "size": 1})
    malware = []
    for doc in cursor:
        malware.append({
            "filename": doc["filename"],
            "threat": "Suspicious" if doc["size"] > 50000 else "Normal",
            "uploaded_at": doc["uploaded_at"].isoformat() + "Z"
        })
    return jsonify(malware), 200


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    PORT = int(os.getenv("PORT", 5000))
    logging.info(f"✅ ThreatSphere backend running at http://127.0.0.1:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=True)
