#!/usr/bin/env python3
"""
🚀 MySQL IDS v4.0 – FINAL (SIGNATURE + ANOMALY BASED)
"""

import time
import re
import os
import ast
from collections import Counter, defaultdict, deque
from datetime import datetime

# ================= CONFIG =================
LOG_FILE = "logs/access.log"
LOOP_INTERVAL = 2
ALERT_TIMEOUT = 30

BRUTE_FORCE_WINDOW = 60
BRUTE_FORCE_THRESHOLD = 5

CRED_STUFF_WINDOW = 60
CRED_STUFF_THRESHOLD = 5

LOGIN_RATE_THRESHOLD = 10
PARAM_THRESHOLD = 6
FLOW_TIMEOUT = 120

# ================= STATE =================
last_position = 0
alert_count = 0
seen_alerts = set()
attack_stats = Counter()

idor_last_uid = {}
login_attempts = defaultdict(list)
usernames_per_ip = defaultdict(set)
request_times = defaultdict(deque)
user_flow = defaultdict(deque)

# ================= INIT =================
if os.path.exists(LOG_FILE):
    with open(LOG_FILE, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        last_position = f.tell()

# ================= LOG READER =================
def read_new_logs():
    global last_position
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r", errors="ignore") as f:
        f.seek(last_position)
        lines = f.readlines()
        last_position = f.tell()
        return [l.strip() for l in lines if l.strip()]

# ================= PARSER =================
def extract_fields(line):
    ip = re.search(r"IP=([\d\.]+)", line)
    url = re.search(r"URL=([^\s]+)", line)
    args = re.search(r"ARGS=({.*?})", line)
    form = re.search(r"FORM=({.*?})", line)

    ip = ip.group(1) if ip else "unknown"
    url = url.group(1) if url else "unknown"

    args_dict, form_dict = {}, {}
    try:
        if args:
            args_dict = ast.literal_eval(args.group(1))
        if form:
            form_dict = ast.literal_eval(form.group(1))
    except:
        pass

    return ip, url, args_dict, form_dict

# ================= SQL INJECTION =================
def detect_sql_injection(url, form):
    if url != "/login" or not form:
        return None

    values = " ".join(str(v).lower() for v in form.values())
    if re.search(r"\b(or|and)\b", values) and re.search(r"['\"]", values):
        return ("SQL Injection", "Auth Bypass", "HIGH")
    return None

# ================= BRUTE FORCE =================
def detect_bruteforce(ip, url):
    if url != "/login":
        return None

    now = time.time()
    login_attempts[ip].append(now)
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t <= BRUTE_FORCE_WINDOW]

    if len(login_attempts[ip]) >= BRUTE_FORCE_THRESHOLD:
        return ("Anomaly Detection", "Brute Force Login", "HIGH")
    return None

# ================= CREDENTIAL STUFFING =================
def detect_credential_stuffing(ip, url, form):
    if url != "/login" or "username" not in form:
        return None

    usernames_per_ip[ip].add(form["username"])
    if len(usernames_per_ip[ip]) >= CRED_STUFF_THRESHOLD:
        return ("Anomaly Detection", "Credential Stuffing", "HIGH")
    return None

# ================= LOGIN RATE SPIKE =================
def detect_login_rate(ip, url):
    if url != "/login":
        return None

    now = time.time()
    request_times[ip].append(now)
    while request_times[ip] and now - request_times[ip][0] > 60:
        request_times[ip].popleft()

    if len(request_times[ip]) > LOGIN_RATE_THRESHOLD:
        return ("Anomaly Detection", "Login Rate Spike", "MEDIUM")
    return None

# ================= IDOR =================
def detect_idor(ip, url, args):
    if url != "/orders" or "uid" not in args:
        return None

    uid = str(args["uid"])
    if ip in idor_last_uid and idor_last_uid[ip] != uid:
        idor_last_uid[ip] = uid
        return ("IDOR", "Object Enumeration", "MEDIUM")

    idor_last_uid[ip] = uid
    return None

# ================= PRICE MANIPULATION =================
def detect_price_manipulation(url, args):
    if url != "/add_to_cart" or "price" not in args:
        return None

    try:
        price = int(args["price"])
        if price <= 0 or price > 100000:
            return ("Business Logic", "Price Manipulation", "MEDIUM")
    except:
        pass
    return None

# ================= PARAMETER FLOOD =================
def detect_param_flood(url, args, form):
    total = len(args) + len(form)
    if total >= PARAM_THRESHOLD:
        return ("Anomaly Detection", "Parameter Pollution", "MEDIUM")
    return None

# ================= FLOW VIOLATION =================
def detect_flow_anomaly(ip, url):
    now = time.time()
    user_flow[ip].append((url, now))
    user_flow[ip] = [(u, t) for u, t in user_flow[ip] if now - t <= FLOW_TIMEOUT]

    urls = [u for u, _ in user_flow[ip]]

    if url in ("/checkout", "/admin") and "/login" not in urls:
        return ("Anomaly Detection", "Broken Access Flow", "HIGH")
    return None

# ================= DECISION =================
def decision_engine(severity):
    return "BLOCK" if severity == "HIGH" else "RATE_LIMIT"

# ================= ALERT =================
def raise_alert(ip, url, attack, subtype, severity, action):
    global alert_count
    alert_count += 1
    attack_stats[f"{attack} → {subtype}"] += 1
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n[{ts}] 🚨 ALERT #{alert_count}")
    print(f"Attack    : {attack}")
    print(f"Subtype   : {subtype}")
    print(f"Severity  : {severity}")
    print(f"IP        : {ip}")
    print(f"URL       : {url}")
    print(f"Action    : {action}")

# ================= MAIN =================
def analyze():
    for line in read_new_logs():
        ip, url, args, form = extract_fields(line)

        detectors = (
            lambda: detect_sql_injection(url, form),
            lambda: detect_bruteforce(ip, url),
            lambda: detect_credential_stuffing(ip, url, form),
            lambda: detect_login_rate(ip, url),
            lambda: detect_idor(ip, url, args),
            lambda: detect_price_manipulation(url, args),
            lambda: detect_param_flood(url, args, form),
            lambda: detect_flow_anomaly(ip, url),
        )

        for d in detectors:
            result = d()
            if result:
                attack, subtype, severity = result
                key = f"{ip}:{subtype}:{int(time.time()//ALERT_TIMEOUT)}"
                if key not in seen_alerts:
                    seen_alerts.add(key)
                    raise_alert(ip, url, attack, subtype, severity, decision_engine(severity))
                break

# ================= SUMMARY =================
def print_summary():
    print("\n" + "=" * 70)
    print("📊 IDS FINAL SUMMARY REPORT")
    print("=" * 70)
    print(f"Total Alerts: {alert_count}\n")
    for k, v in attack_stats.items():
        print(f"{k:<55} {v}")
    print("=" * 70)

# ================= RUN =================
def main():
    print("🚀 MySQL IDS v4.0 STARTED")
    print(f"📁 Monitoring {LOG_FILE}")
    print("-" * 60)
    try:
        while True:
            analyze()
            time.sleep(LOOP_INTERVAL)
    except KeyboardInterrupt:
        print("\n🛑 IDS STOPPED")
        print_summary()

if __name__ == "__main__":
    main()
