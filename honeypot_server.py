import asyncio
from logger import log_event
from enrichment import geoip_lookup, virustotal_ip_check

async def handle_client(reader, writer, service):
    addr = writer.get_extra_info("peername")
    ip = addr[0]
    geo = geoip_lookup(ip)
    vt = virustotal_ip_check(ip)
    log_event(f"{service}_connection", {"ip": ip, "port": addr[1], "geo": geo, "vt": vt})
    if vt.get("malicious", 0) > 0:
        log_event("alert", {"ip": ip, "reason": f"VirusTotal reports {vt['malicious']} engines flagged this IP."})
    if service == "ssh":
        writer.write(b"SSH-2.0-OpenSSH_8.4p1 Debian-5\r\n")
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=10.0)
            log_event("ssh_attempt", {"ip": ip, "input": data.decode(errors='replace'), "geo": geo, "vt": vt})
            writer.write(b"Permission denied, please try again.\r\n")
            await writer.drain()
        except asyncio.TimeoutError:
            pass
    elif service == "http":
        data = await reader.read(1024)
        req = data.decode(errors='replace')
        log_event("http_request", {"ip": ip, "request": req, "geo": geo, "vt": vt})
        if req.startswith("POST"):
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nFake POST received.\n")
        else:
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFake 404 page\n")
        await writer.drain()
    writer.close()

async def main():
    ssh_server = await asyncio.start_server(lambda r, w: handle_client(r, w, "ssh"), "0.0.0.0", 2222)
    http_server = await asyncio.start_server(lambda r, w: handle_client(r, w, "http"), "0.0.0.0", 8080)
    async with ssh_server, http_server:
        await asyncio.gather(ssh_server.serve_forever(), http_server.serve_forever())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Stopped honeypot.")
