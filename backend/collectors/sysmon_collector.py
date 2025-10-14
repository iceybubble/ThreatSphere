# Inside VM
import win32evtlog
from pymongo import MongoClient

log_type = "Microsoft-Windows-Sysmon/Operational"
hand = win32evtlog.OpenEventLog('localhost', log_type)

client = MongoClient("mongodb://<host_machine>:27017/")
db = client["threatsphere"]
collection = db["sandbox_logs"]

flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
events = win32evtlog.ReadEventLog(hand, flags, 0)

for event in events:
    collection.insert_one({
        "event_id": event.EventID,
        "time": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
        "details": event.StringInserts
    })
