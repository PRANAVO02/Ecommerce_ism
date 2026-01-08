import time
import re
from collections import defaultdict

LOG_FILE = "logs/access.log"

# =========================
# SIGNATURE-BASED SETTINGS
# =========================
SQLI_PATTERNS = [
    r"(\bor\b\s+1=1)",
    r"union\s+select",
    r"--",
    r";",
    r"drop\s+table",
    r"select\s+\*"
]

# =========================
# ANOMALY-BASED BASELINES
# =========================
REQUEST_LIMIT = 20     # per minute (sensitive endpoints)
LOGIN_LIMIT = 5        # per minute
MAX_INPUT_LENGTH = 100

request_counter = defaultdict(list)
login_counter = defaultdict(list)
idor_counter = defaultdict(int)

# =========================
# FILE POINTER (IMPORTANT)
# =========================
last_position = 0

def read_new_logs():
    """Read only newly added log lines"""
    global last_position
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(last_position)
        lines = f.readlines()
        last_position = f.tell()
    return lines

def extract_ip_url(line):
    ip = re.search(r"IP=([\d\.]+)", line)
    url = re.search(r"URL=([^\s]+)", line)
    args = re.search(r"ARGS=(\{.*\})", line)

    return (
        ip.group(1) if ip else "unknown",
        url.group(1) if url else "unknown",
        args.group(1) if args else ""
    )

# =========================
# SIGNATURE DETECTION
# =========================
def detect_signature_attack(line):
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return "SQL Injection"
    return None

# =========================
# ANOMALY DETECTION
# =========================
def detect_anomaly(ip, url, args):
    now = time.time()

    # Ignore static resources completely
    if url.startswith("/static"):
        return None

    # -------------------------
    # Request rate anomaly
    # -------------------------
    request_counter[ip].append(now)
    request_counter[ip] = [t for t in request_counter[ip] if now - t < 60]

    if url in ["/login", "/admin", "/orders", "/checkout"]:
        if len(request_counter[ip]) > REQUEST_LIMIT:
            return "High Request Rate on Sensitive Endpoint"

    # -------------------------
    # Brute force anomaly
    # -------------------------
    if url == "/login":
        login_counter[ip].append(now)
        login_counter[ip] = [t for t in login_counter[ip] if now - t < 60]

        if len(login_counter[ip]) > LOGIN_LIMIT:
            return "Brute Force Login Attempt"

    # -------------------------
    # Input length anomaly
    # -------------------------
    if len(args) > MAX_INPUT_LENGTH:
        return "Abnormally Long Input (Unknown Attack)"

    # -------------------------
    # IDOR enumeration anomaly
    # -------------------------
    if "/orders" in url and "uid=" in args:
        idor_counter[ip] += 1
        if idor_counter[ip] > 3:
            return "ID Enumeration (IDOR Attack)"

    # -------------------------
    # Business logic anomaly
    # -------------------------
    if "price=" in args:
        try:
            price = int(re.search(r"price=(\d+)", args).group(1))
            if price <= 0 or price > 100000:
                return "Price Manipulation (Business Logic Abuse)"
        except:
            pass

    return None

# =========================
# MAIN ANALYSIS LOOP
# =========================
def analyze():
    logs = read_new_logs()

    for line in logs:
        ip, url, args = extract_ip_url(line)

        # ---------- SIGNATURE ----------
        sig = detect_signature_attack(line)
        if sig:
            print("\n[ALERT] 🚨 SIGNATURE ATTACK DETECTED")
            print(f"Type     : {sig}")
            print(f"Severity : HIGH")
            print(f"IP       : {ip}")
            print(f"Request  : {line.strip()}")
            continue

        # ---------- ANOMALY ----------
        anomaly = detect_anomaly(ip, url, args)
        if anomaly:
            print("\n[ALERT] ⚠️ ANOMALY DETECTED")
            print(f"Type     : {anomaly}")
            print(f"Severity : MEDIUM")
            print(f"IP       : {ip}")
            print(f"Request  : {line.strip()}")

# =========================
# RUN IDS
# =========================
if __name__ == "__main__":
    print("[IDS] Hybrid IDS (Signature + Anomaly) Running...")
    while True:
        analyze()
        time.sleep(5)
