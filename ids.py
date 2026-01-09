import time
import re
from collections import defaultdict
from datetime import datetime

LOG_FILE = "logs/access.log"

# ================= SIGNATURE PATTERNS =================
# Classic keyword-based SQLi
SQLI_KEYWORD_PATTERNS = [
    r"\bor\b\s+\d+\s*=\s*\d+",
    r"\band\b\s+\d+\s*=\s*\d+",
    r"union\s+select",
    r"drop\s+table",
    r"--",
    r";",
    r"select\s+\*"
]

# Logic-based SQLi (NO errors, NO keywords)
SQLI_LOGIC_PATTERNS = [
    r"\w+\s*=\s*\w+",        # a=a , x=y
    r"\d+\s*=\s*\d+",        # 1=1
    r"\w+'\s*=\s*'\w+",      # 'a'='a'
    r"\bor\b|\band\b",       # logical operators
]

# ================= ANOMALY BASELINES =================
REQUEST_LIMIT = 20
LOGIN_LIMIT = 3
MAX_INPUT_LENGTH = 80

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
    form = re.search(r"FORM=(\{.*?\})", line)
    args = re.search(r"ARGS=(\{.*?\})", line)

    payload = (form.group(1) if form else "") + " " + (args.group(1) if args else "")

    return (
        ip.group(1) if ip else "unknown",
        url.group(1) if url else "unknown",
        payload.lower()
    )

# ================= SQL INJECTION DETECTION =================
def detect_sql_injection(url, payload):
    # --- Keyword-based SQLi ---
    for pattern in SQLI_KEYWORD_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            return "SQL Injection (Keyword-Based)"

    # --- Logic-based SQLi (IMPORTANT FIX) ---
    if url == "/login":
        for pattern in SQLI_LOGIC_PATTERNS:
            if re.search(pattern, payload):
                return "SQL Injection (Logic-Based)"

    return None

# ================= ANOMALY DETECTION =================
def detect_anomaly(ip, url, payload):
    now = time.time()

    if url.startswith("/static"):
        return None

    request_counter[ip].append(now)
    request_counter[ip] = [t for t in request_counter[ip] if now - t < 60]

    if url == "/login":
        login_counter[ip].append(now)
        login_counter[ip] = [t for t in login_counter[ip] if now - t < 60]
        if len(login_counter[ip]) > LOGIN_LIMIT:
            return "Brute Force Login"

    if len(payload) > MAX_INPUT_LENGTH:
        return "Abnormally Structured Input"

    if "/orders" in url and "uid=" in payload:
        idor_counter[ip] += 1
        if idor_counter[ip] > 3:
            return "ID Enumeration (IDOR)"

    return None

# ================= DECISION ENGINE =================
def decision_engine(ip, attack_type, severity):
    now = time.time()
    attack_history[ip].append((attack_type, severity, now))

    attack_history[ip] = [
        a for a in attack_history[ip] if now - a[2] < 300
    ]

    high = sum(1 for a in attack_history[ip] if a[1] == "HIGH")

    if severity == "HIGH":
        return "IMMEDIATE RESPONSE" if high < 2 else "BLOCK + SELF-HEAL"

    return "MONITOR"

# ================= MAIN LOOP =================
def analyze():
    logs = read_new_logs()

    for line in logs:
        ip, url, payload = extract_fields(line)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        sql = detect_sql_injection(url, payload)
        if sql:
            action = decision_engine(ip, sql, "HIGH")

            print(f"\n[{timestamp}] [ALERT] 🚨 SQL INJECTION DETECTED")
            print(f"Type     : {sql}")
            print(f"Severity : HIGH")
            print(f"IP       : {ip}")
            print(f"Action   : {action}")
            continue

        anomaly = detect_anomaly(ip, url, payload)
        if anomaly:
            action = decision_engine(ip, anomaly, "MEDIUM")

            print(f"\n[{timestamp}] [ALERT] ⚠️ ANOMALY DETECTED")
            print(f"Type     : {anomaly}")
            print(f"Severity : MEDIUM")
            print(f"IP       : {ip}")
            print(f"Action   : {action}")

# ================= RUN =================
if __name__ == "__main__":
    print("[IDS] Hybrid IDS + Logic-Based SQLi Detection Running...")
    while True:
        analyze()
        time.sleep(5)
