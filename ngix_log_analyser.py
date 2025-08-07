import re
import subprocess
from collections import defaultdict, Counter

log_path = "/var/log/nginx/access.log"

SUSPICIOUS_PATHS = [
    "/admin", "/login", "/wp-admin", "/setup", "/phpmyadmin", "/.env",
    "/cgi-bin/", "/vendor/", "/eval-stdin.php", "/hello.world", "/boaform/"
]
SUSPICIOUS_AGENTS = ["sqlmap", "nikto", "fuzz", "scanner", "dirbuster", "curl", "wget"]
SUSPICIOUS_PARAMS = ["cmd=", "exec=", "id=", "select ", "--", "' OR ", "\" OR "]
REQUEST_THRESHOLD = 20

country_cache = {}

def get_country(ip):
    if ip in country_cache:
        return country_cache[ip]

    try:
        result = subprocess.run(
            ["whois", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3
        )
        match = re.search(r"(?i)^country:\s*([A-Z]{2})", result.stdout, re.MULTILINE)
        country = match.group(1) if match else "??"
    except Exception:
        country = "??"

    country_cache[ip] = country
    return country

log_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<agent>[^"]+)"'
)

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
        time = data["time"]
        url = data["url"]
        method = data["method"]
        status = int(data["status"])
        agent = data["agent"].lower()

        suspicious_ips[ip] += 1

        if any(susp in agent for susp in SUSPICIOUS_AGENTS):
            suspicious_agents.append((ip, agent, url, time))

        if method == "POST":
            suspicious_requests.append((ip, method, url, time))

        if any(path in url for path in SUSPICIOUS_PATHS):
            suspicious_requests.append((ip, method, url, time))

        if any(param in url.lower() for param in SUSPICIOUS_PARAMS):
            suspicious_requests.append((ip, method, url, time))

        if status >= 400:
            errors.append((ip, status, url, time))

# 🔎 Ausgabe

print("\n📛 Fehlerhafte Anfragen (4xx / 5xx):")
for ip, status, url, time in errors:
    print(f"[{ip} | {get_country(ip)} | {time}] {status} → {url}")

print("\n🚩 POST- oder verdächtige Zugriffe:")
for ip, method, url, time in suspicious_requests:
    print(f"[{ip} | {get_country(ip)} | {time}] {method} → {url}")

print("\n🕵️ Verdächtige User-Agents:")
for ip, agent, url, time in suspicious_agents:
    print(f"[{ip} | {get_country(ip)} | {time}] '{agent}' → {url}")

print("\n📈 IPs mit hoher Anfragefrequenz:")
for ip, count in Counter(suspicious_ips).most_common():
    if count >= REQUEST_THRESHOLD:
        print(f"{ip} ({get_country(ip)}) → {count} Anfragen")
