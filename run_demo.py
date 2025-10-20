import asyncio, socket, threading, time
import honeypot_server

def start_server():
    asyncio.run(honeypot_server.main())

t = threading.Thread(target=start_server, daemon=True)
t.start()
time.sleep(2)

# Simulate SSH client
s = socket.socket()
s.connect(("127.0.0.1", 2222))
print(s.recv(1024).decode())
s.sendall(b"admin:password\n")
print(s.recv(1024).decode())
s.close()

# Simulate HTTP GET
s2 = socket.socket()
s2.connect(("127.0.0.1", 8080))
s2.sendall(b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n")
print(s2.recv(1024).decode())
s2.close()

# Simulate HTTP POST
s3 = socket.socket()
s3.connect(("127.0.0.1", 8080))
s3.sendall(b"POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\n\r\nuser=admin")
print(s3.recv(1024).decode())
s3.close()

time.sleep(2)
print("Demo finished. Logs written to logs/events.jsonl")
