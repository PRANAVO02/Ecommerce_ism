import json
import os
import time

BASE_DIR = "security"

FILES = {
    "blocked": "blocked_ips.json",
    "rate": "rate_limited_ips.json",
    "quarantine": "quarantined_ips.json"
}

def _load(file):
    path = os.path.join(BASE_DIR, file)
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)

def _save(file, data):
    path = os.path.join(BASE_DIR, file)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# -------- ENFORCEMENT ACTIONS --------
def block_ip(ip):
    data = _load(FILES["blocked"])
    data[ip] = int(time.time())
    _save(FILES["blocked"], data)

def rate_limit_ip(ip):
    data = _load(FILES["rate"])
    data[ip] = int(time.time())
    _save(FILES["rate"], data)

def quarantine_ip(ip):
    data = _load(FILES["quarantine"])
    data[ip] = int(time.time())
    _save(FILES["quarantine"], data)

# -------- CHECKS --------
def is_blocked(ip):
    return ip in _load(FILES["blocked"])

def is_rate_limited(ip):
    return ip in _load(FILES["rate"])

def is_quarantined(ip):
    return ip in _load(FILES["quarantine"])