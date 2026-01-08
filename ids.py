import time
import re
from collections import defaultdict
from datetime import datetime

LOG_FILE = "logs/access.log"

# ================= SIGNATURE PATTERNS =================
SQLI_PATTERNS = [
    r"(\bor\b\s+1=1)",
    r"union\s+select",
    r"--",
    r";",
    r"drop\s+table",
    r"select\s+\*"
]

# ================= ANOMALY BASELINES =================
REQUEST_LIMIT = 20
LOGIN_LIMIT = 3
MAX_INPUT_LENGTH = 100

request_counter = defaultdict(list)
login_counter = defaultdict(list)
idor_counter = defaultdict(int)

# ================= DECISION ENGINE STATE =================
attack_history = defaultdict(list)

# ================= FILE POINTER =================
last_position = 0

def read_new_logs():
    global last_position
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(last_position)
        lines = f.readlines()
        last_position = f.tell()
    return lines

def extract_fields(line):
    ip = re.search(r"IP=([\d\.]+)", line)
    url = re.search(r"URL=([^\s]+)", line)
    args = re.search(r"ARGS=(\{.*?\})", line)
    form = re.search(r"FORM=(\{.*?\})", line)

    payload = (args.group(1) if args else "") + " " + (form.group(1) if form else "")

    return (
        ip.group(1) if ip else "unknown",
        url.group(1) if url else "unknown",
        payload
    )

# ================= SIGNATURE DETECTION =================
def detect_signature(line):
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return "SQL Injection"
    return None

# ================= ANOMALY DETECTION =================
def detect_anomaly(ip, url, payload):
    now = time.time()

    if url.startswith("/static"):
        return None

    request_counter[ip].append(now)
    request_counter[ip] = [t for t in request_counter[ip] if now - t < 60]

    if url in ["/login", "/admin", "/orders", "/checkout"]:
        if len(request_counter[ip]) > REQUEST_LIMIT:
            return "High Request Rate"

    if url == "/login":
        login_counter[ip].append(now)
        login_counter[ip] = [t for t in login_counter[ip] if now - t < 60]
        if len(login_counter[ip]) > LOGIN_LIMIT:
            return "Brute Force Login"

    if len(payload) > MAX_INPUT_LENGTH:
        return "Abnormally Long Input"

    if "/orders" in url and "uid=" in payload:
        idor_counter[ip] += 1
        if idor_counter[ip] > 3:
            return "ID Enumeration (IDOR)"

    if "price=" in payload:
        try:
            price = int(re.search(r"price=(\d+)", payload).group(1))
            if price <= 0 or price > 100000:
                return "Price Manipulation"
        except:
            pass

    return None

# ================= DECISION ENGINE =================
def decision_engine(ip, attack_type, severity):
    now = time.time()
    attack_history[ip].append((attack_type, severity, now))

    attack_history[ip] = [
        a for a in attack_history[ip] if now - a[2] < 300
    ]

    high_count = sum(1 for a in attack_history[ip] if a[1] == "HIGH")
    medium_count = sum(1 for a in attack_history[ip] if a[1] == "MEDIUM")

    if severity == "HIGH":
        if high_count >= 2:
            return "BLOCK + SELF-HEAL"
        return "IMMEDIATE RESPONSE"

    if severity == "MEDIUM":
        if medium_count >= 3:
            return "DECEPTION"
        return "MONITOR"

    return "LOG"

# ================= MAIN LOOP =================
def analyze():
    logs = read_new_logs()

    for line in logs:
        ip, url, payload = extract_fields(line)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        sig = detect_signature(line)
        if sig:
            severity = "HIGH"
            action = decision_engine(ip, sig, severity)

            print(f"\n[{timestamp}] [ALERT] 🚨 SIGNATURE ATTACK")
            print(f"Type     : {sig}")
            print(f"Severity : {severity}")
            print(f"IP       : {ip}")
            print(f"Action   : {action}")
            continue

        anomaly = detect_anomaly(ip, url, payload)
        if anomaly:
            severity = "MEDIUM"
            action = decision_engine(ip, anomaly, severity)

            print(f"\n[{timestamp}] [ALERT] ⚠️ ANOMALY DETECTED")
            print(f"Type     : {anomaly}")
            print(f"Severity : {severity}")
            print(f"IP       : {ip}")
            print(f"Action   : {action}")

# ================= RUN =================
if __name__ == "__main__":
    print("[IDS] Hybrid IDS + Decision Engine + Timestamp Running...")
    while True:
        analyze()
        time.sleep(5)
