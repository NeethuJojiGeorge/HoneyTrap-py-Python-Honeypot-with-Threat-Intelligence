import json

with open("logs/events.jsonl") as f:
    entries = [json.loads(line) for line in f]

print(f"\nParsed {len(entries)} total events.")
for e in entries:
    ip = e['data'].get('ip')
    geo = e['data'].get('geo', {})
    vt = e['data'].get('vt', {})
    print(f"{e['timestamp']} | {e['type']} | {ip} | Geo: {geo} | VT: {vt}")
    if e['type'] == "alert":
        print(f"*** ALERT: {e['data']}")
