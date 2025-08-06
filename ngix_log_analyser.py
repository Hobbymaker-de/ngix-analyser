'''
Aufruf benötigt sudo!
z.B.: sudo /venv/bin/python ./ngix_log_analyse.py

Was das Skript erkennt (standardmäßig):
HTTP-Fehlercodes wie 4xx, 5xx (z. B. 404, 500)

Viele Anfragen von einer IP (mögliche Brute-Force oder Scan-Versuche)

Verdächtige User-Agents (z. B. sqlmap, nikto, curl, etc.)

POST-Requests (z. B. unerwartete Loginversuche)

Zugriffe auf Admin-, Login- oder Setup-Seiten

Requests mit verdächtigen Parametern (?cmd=, ?id=1'--, etc.)
'''

import re
from collections import defaultdict, Counter

# Konfiguration: was ist kritisch?
SUSPICIOUS_PATHS = ["/admin", "/login", "/wp-admin", "/setup", "/phpmyadmin", "/.env"]
SUSPICIOUS_AGENTS = ["sqlmap", "nikto", "fuzz", "scanner", "dirbuster", "curl", "wget"]
SUSPICIOUS_PARAMS = ["cmd=", "exec=", "id=", "select ", "--", "' OR ", "\" OR "]
REQUEST_THRESHOLD = 20  # z. B. mehr als 20 Anfragen pro IP im Log

log_path = "/var/log/nginx/access.log"  # Pfad zur Nginx-Logdatei

# Regex für Combined Log Format
log_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<agent>[^"]+)"'
)

# Daten sammeln
errors = []
suspicious_ips = defaultdict(int)
suspicious_agents = []
suspicious_requests = []

with open(log_path, "r", encoding="utf-8") as f:
    for line in f:
        match = log_pattern.match(line)
        if not match:
            continue

        data = match.groupdict()
        ip = data["ip"]
        url = data["url"]
        method = data["method"]
        status = int(data["status"])
        agent = data["agent"].lower()

        # Zähle Anfragen pro IP
        suspicious_ips[ip] += 1

        # Finde verdächtige User-Agents
        if any(susp in agent for susp in SUSPICIOUS_AGENTS):
            suspicious_agents.append((ip, agent, url))

        # Finde POST-Requests
        if method == "POST":
            suspicious_requests.append((ip, method, url))

        # Finde verdächtige URLs
        if any(path in url for path in SUSPICIOUS_PATHS):
            suspicious_requests.append((ip, method, url))

        if any(param in url.lower() for param in SUSPICIOUS_PARAMS):
            suspicious_requests.append((ip, method, url))

        # Fehlerhafte Zugriffe (4xx, 5xx)
        if status >= 400:
            errors.append((ip, status, url))

# --- Ausgabe ---

print("\n📛 Fehlerhafte Anfragen (4xx / 5xx):")
for ip, status, url in errors:
    print(f"[{ip}] {status} → {url}")

print("\n🚩 POST- oder verdächtige Zugriffe:")
for ip, method, url in suspicious_requests:
    print(f"[{ip}] {method} → {url}")

print("\n🕵️ Verdächtige User-Agents:")
for ip, agent, url in suspicious_agents:
    print(f"[{ip}] '{agent}' → {url}")

print("\n📈 IPs mit hoher Anfragefrequenz:")
for ip, count in Counter(suspicious_ips).most_common():
    if count >= REQUEST_THRESHOLD:
        print(f"{ip} → {count} Anfragen")

