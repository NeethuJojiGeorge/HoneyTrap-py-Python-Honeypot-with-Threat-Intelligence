# HoneyTrap-py — Python Honeypot with Threat Intelligence

Simulates SSH and HTTP, logs attacker payloads, enriches with GeoIP, and checks IPs against VirusTotal.  

## Quick Start

1. `pip install -r requirements.txt`
2. Download GeoLite2-City.mmdb and place in `enrichment/`
3. Get a VirusTotal API key, set it: `export VT_API_KEY="your_api_key"`
4. `python run_demo.py`
5. View logs in `logs/events.jsonl`
6. Summarize: `python parse_logs.py`

## Features

- Async SSH/HTTP emulation
- Logs all connections and payloads
- GeoIP enrichment for attacker IPs
- VirusTotal IP reputation check and alerting
- Demo script for local testing
- Log parser for quick analysis


