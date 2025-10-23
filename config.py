import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "threatsphere")
LOG_FILE = os.getenv("LOG_FILE", "server.log")
PORT = int(os.getenv("PORT", 5000))
API_KEY = os.getenv("API_KEY", "ca2dc42dd9cfa70355d1dfd62e0d9d4287b22b2230e924524e473e8cd046cbef")
