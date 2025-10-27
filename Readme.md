🧠 ThreatSphere

ThreatSphere is a sandbox environment for safely analyzing ransomware and malware behavior.
It provides a controlled, isolated, and automated setup to execute malicious files, capture their activity, and generate structured logs and reports — all without risking your host system.

🚀 Purpose

The goal of ThreatSphere is to enable researchers, analysts, and cybersecurity learners to:

🧩 Run suspicious executables safely inside a sandbox (VM or container).

🔍 Monitor system behavior: file modifications, process creation, network activity, registry edits, etc.

🪵 Collect logs and store them securely in a backend database (MongoDB).

📊 Generate reports for malware analysis or bug bounty research.

🧠 Learn malware behavior hands-on in a reproducible and safe way.


💡 Why We’re Building ThreatSphere

```
Goal	                                            Description
🧱 Safe malware testing	        Execute ransomware or trojans inside an isolated environment without endangering your real system.
⚙️ Automated logging	        Automatically capture file, process, and network events using a Python logging backend.
📁 Data-driven analysis	        Store logs in MongoDB for correlation, searching, and deeper investigation.
🧪 Reproducible lab	            Build a repeatable setup for testing multiple samples consistently.
🎓 Educational tool	            Help students and professionals understand malware behavior step-by-step.
```

🏗️ Core Components

1️⃣ Sandbox Environment

A Virtual Machine, Container, or Isolated Host to safely execute malware samples.

Examples: VirtualBox, VMware, QEMU, or Docker (for lightweight analysis).

2️⃣ Behavior Logging Backend

Python + Flask API that collects logs and sends them to MongoDB.

Monitors activity like:

File/Folder creation & deletion

Network calls (sockets, requests)

Registry or process changes

Custom event logs from malware samples

3️⃣ MongoDB Database

Stores all collected logs in structured form (timestamp, type, details, etc.).

Can be hosted locally (Compass) or on the cloud (MongoDB Atlas).

4️⃣ Analysis Dashboard (optional)

A web or terminal dashboard to visualize logs.

Filter by date, type, or severity.

Export results as CSV or JSON for sharing.

5️⃣ Automation Layer (future goal)

Automatically run multiple malware samples.

Collect logs → Analyze → Generate detailed reports.

⚙️ Tech Stack

```
Component	         Technology
Backend	             Python (Flask)
Database	         MongoDB / MongoDB Atlas
Frontend	         HTML / JS Dashboard (optional)
Virtualization	     VirtualBox / VMware / Docker
Logging	             JSON-based event collection
Reporting	         CSV / JSON exports
```

🧰 Installation & Setup

1️⃣ Clone the repository

```
git clone https://github.com/yourusername/ThreatSphere.git
cd ThreatSphere
``` 


2️⃣ Create and activate a virtual environment

```
python -m venv venv
source venv/bin/activate   # On Linux/macOS
venv\Scripts\activate      # On Windows
```


3️⃣ Install dependencies

```
pip install -r requirements.txt
```

4️⃣ Set up MongoDB connection

Create a .env file in your project root:

5️⃣ Run the backend

```
python server.py
```

Backend will start on:

```
👉 http://127.0.0.1:5000
```

How to access the frontend

After starting the backend (python server.py), open your browser and navigate to:

```
http://127.0.0.1:5000/
```


The Flask app serves the dashboard at the root route (/) — the frontend files (templates/index.html and /static/*) are served by Flask, so you do not need a separate static server.
🧪 Testing Log Collection

Send a test log:

```
curl -X POST http://127.0.0.1:5000/log -H "Content-Type: application/json" -d '{"event": "file_created", "path": "/tmp/test.txt"}'
```

If configured correctly, the event will be stored in MongoDB.


📊 Output Example

```
{
  "timestamp": "2025-10-25T12:30:01Z",
  "event": "file_created",
  "path": "C:\\Users\\Sandbox\\Desktop\\payload.exe",
  "category": "filesystem",
  "severity": "medium"
}

```

🔒 Safety Notes

⚠️ Always run ThreatSphere inside a virtualized or isolated environment.
Never execute real ransomware samples on your host system.

Suggested setup:

Use VirtualBox / VMware with no network bridge (host-only network).

Snapshot before running samples.

Use read-only shares if needed.

🧠 Future Enhancements

✅ Advanced network activity capture (via Scapy or Wireshark API).

✅ Real-time event dashboard using Flask-SocketIO.

✅ Sandbox orchestration for multiple malware samples.

✅ Automatic behavior categorization (ransomware, spyware, etc.).

✅ Threat intelligence report generation.

👨‍💻 Author

```
Project: ThreatSphere
Purpose: Educational Malware Analysis Environment
Created by: iceybubble
Built with: Python, Flask, MongoDB
```

📜 License

This project is intended for educational and research purposes only.
Do not use ThreatSphere for illegal or unethical activities.