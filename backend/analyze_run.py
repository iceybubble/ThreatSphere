# analyze_run.py
import json, csv, sys, os
from datetime import datetime
from collections import Counter

infile = sys.argv[1] if len(sys.argv)>1 else "exports/run_recent.json"
out_csv = infile.replace(".json", ".csv")
report_txt = infile.replace(".json", "_report.txt")

with open(infile, "r", encoding="utf-8") as f:
    docs = json.load(f)

# Normalize docs (if API returned list or wrapped)
if isinstance(docs, dict) and docs.get("hits"):
    docs = docs["hits"]["hits"]

events = []
for d in docs:
    # if wrapped from ES style: adapt, else direct
    if isinstance(d, dict) and "_source" in d:
        src = d["_source"]
    else:
        src = d
    rec = {
        "id": src.get("_id") or src.get("id") or "",
        "source": src.get("source"),
        "level": src.get("level"),
        "summary": (src.get("summary") or "")[:1000],
        "files_changed": src.get("files_changed") or [],
        "received_at": src.get("received_at") or src.get("meta",{}).get("collected_at") or ""
    }
    events.append(rec)

# CSV export: one row per event, files_changed length & sample path
with open(out_csv, "w", newline="", encoding="utf-8") as csvf:
    w = csv.writer(csvf)
    w.writerow(["id","source","level","received_at","summary","num_files_changed","sample_file_changed"])
    for e in events:
        fc = e["files_changed"] or []
        sample = fc[0]["path"] if fc else ""
        w.writerow([e["id"], e["source"], e["level"], e["received_at"], e["summary"].replace("\n"," "), len(fc), sample])

# Quick summary report
levels = Counter(e["level"] for e in events if e["level"])
sources = Counter(e["source"] for e in events if e["source"])
total_files_changed = sum(len(e["files_changed"]) for e in events)

with open(report_txt, "w", encoding="utf-8") as rf:
    rf.write(f"ThreatSphere run analysis - {datetime.utcnow().isoformat()}Z\n")
    rf.write(f"Input: {infile}\n\n")
    rf.write(f"Total events: {len(events)}\n")
    rf.write(f"Total files_changed entries: {total_files_changed}\n\n")
    rf.write("Top levels:\n")
    for lvl, c in levels.most_common():
        rf.write(f"  {lvl}: {c}\n")
    rf.write("\nTop sources:\n")
    for s,c in sources.most_common():
        rf.write(f"  {s}: {c}\n")
    rf.write("\nSample events (first 10):\n")
    for e in events[:10]:
        rf.write(f"- [{e['received_at']}] {e['source']} {e['level']} files={len(e['files_changed'])} summary={e['summary'][:120]}\n")

print("Wrote:", out_csv, report_txt)
