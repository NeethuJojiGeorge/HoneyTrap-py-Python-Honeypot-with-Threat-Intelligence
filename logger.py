import json, os, datetime

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, "events.jsonl")

def log_event(event_type, data):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "type": event_type,
        "data": data
    }
    with open(LOG_PATH, "a") as f:
        json.dump(entry, f)
        f.write("\n")
