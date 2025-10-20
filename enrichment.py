import geoip2.database
import os
import requests

DB_PATH = os.path.join("enrichment", "GeoLite2-City.mmdb")
VT_API_KEY = os.environ.get("VT_API_KEY")  # Set your VirusTotal API key

def geoip_lookup(ip):
    if not os.path.exists(DB_PATH):
        return {"error": "GeoIP DB missing"}
    try:
        with geoip2.database.Reader(DB_PATH) as reader:
            response = reader.city(ip)
            return {
                "country": response.country.name,
                "city": response.city.name,
                "lat": response.location.latitude,
                "lon": response.location.longitude
            }
    except Exception:
        return {"error": "lookup failed"}

def virustotal_ip_check(ip):
    if not VT_API_KEY:
        return {"error": "No VT API key"}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            malicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            return {"malicious": malicious}
        else:
            return {"error": f"VT status {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}
