import json
import time
import threading
from pathlib import Path
from collections import deque

import joblib
import pandas as pd
import numpy as np

PIPE_PATH = "ids_pipeline.joblib"
ZEEK_DIR  = "/Users/cghute/zeek-ids"
CONN_LOG  = f"{ZEEK_DIR}/conn.log"
HTTP_LOG  = f"{ZEEK_DIR}/http.log"

THRESHOLD = 0.5  # adjust later

pipe = joblib.load(PIPE_PATH)

def safe_float(x, default=0.0) -> float:
    try:
        if x is None:
            return default
        return float(x)
    except Exception:
        return default

def safe_int(x, default=0) -> int:
    try:
        if x is None:
            return default
        return int(float(x))
    except Exception:
        return default

def follow(path: str):
    p = Path(path)
    while not p.exists():
        time.sleep(0.5)
    with p.open("r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line

# --- Zeek conn -> model row (UNSW-like feature names) ---
def to_model_row(evt: dict) -> pd.DataFrame:
    row = {
        "dur": safe_float(evt.get("duration"), 0.0),
        "proto": (evt.get("proto") or "unknown"),
        "service": (evt.get("service") or "unknown"),
        "state": (evt.get("conn_state") or "UNK"),
        "sbytes": safe_float(evt.get("orig_bytes"), 0.0),
        "dbytes": safe_float(evt.get("resp_bytes"), 0.0),
        "spkts": safe_float(evt.get("orig_pkts"), 0.0),
        "dpkts": safe_float(evt.get("resp_pkts"), 0.0),
    }

    required = list(pipe.feature_names_in_)
    for c in required:
        if c not in row:
            row[c] = 0

    X = pd.DataFrame([row])[required].replace([np.inf, -np.inf], np.nan)
    return X

# --- HTTP correlation cache ---
http_by_uid = {}
http_uid_order = deque(maxlen=50000)
http_lock = threading.Lock()

def cache_http(uid: str, info: dict):
    if not uid:
        return
    with http_lock:
        http_by_uid[uid] = info
        http_uid_order.append(uid)
        # trim old
        if len(http_uid_order) == http_uid_order.maxlen:
            for _ in range(1000):
                if not http_uid_order:
                    break
                old = http_uid_order.popleft()
                http_by_uid.pop(old, None)

def parse_http_line(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Try JSON first
    if line.startswith("{") and line.endswith("}"):
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            return None
        uid = evt.get("uid")
        info = {
            "ts": evt.get("ts"),
            "host": evt.get("host"),
            "method": evt.get("method"),
            "uri": evt.get("uri"),
            "user_agent": evt.get("user_agent"),
            "status_code": evt.get("status_code"),
            "referrer": evt.get("referrer"),
        }
        return uid, info

    # Fallback: TSV (your earlier format)
    parts = line.split("\t")
    if len(parts) < 17:
        return None

    uid = parts[1]
    info = {
        "ts": parts[0],
        "method": parts[7],
        "host": parts[8],
        "uri": parts[9],
        "referrer": parts[10],
        "user_agent": parts[12],
        "status_code": parts[15],
    }
    return uid, info

def http_tailer():
    for line in follow(HTTP_LOG):
        parsed = parse_http_line(line)
        if not parsed:
            continue
        uid, info = parsed
        cache_http(uid, info)

threading.Thread(target=http_tailer, daemon=True).start()

print("Real-time scoring started.")
print("Watching conn:", CONN_LOG)
print("Watching http:", HTTP_LOG, "(correlate on alerts)")
print("Threshold:", THRESHOLD)

for line in follow(CONN_LOG):
    line = line.strip()
    if not line or line.startswith("#"):
        continue

    try:
        evt = json.loads(line)
    except json.JSONDecodeError:
        continue

    if "uid" not in evt or "proto" not in evt:
        continue

    uid = evt.get("uid")
    X = to_model_row(evt)
    score = float(pipe.predict_proba(X)[0, 1])

    oh = evt.get("id.orig_h", "-")
    op = evt.get("id.orig_p", "-")
    rh = evt.get("id.resp_h", "-")
    rp = evt.get("id.resp_p", "-")
    proto = evt.get("proto", "-")
    svc = evt.get("service", "-")
    dur = safe_float(evt.get("duration"), 0.0)
    ob = safe_int(evt.get("orig_bytes"), 0)
    rb = safe_int(evt.get("resp_bytes"), 0)

    print(f"score={score:.6f} uid={uid} {oh}:{op} -> {rh}:{rp} proto={proto} service={svc} dur={dur:.3f}s bytes={ob}/{rb}")

    if score >= THRESHOLD:
        with http_lock:
            http_info = http_by_uid.get(uid)

        print("\n=== IDS ALERT ===")
        print(f"Score     : {score:.6f} (threshold={THRESHOLD})")
        print(f"UID       : {uid}")
        print(f"Flow      : {oh}:{op} -> {rh}:{rp}")
        print(f"Proto/Svc : {proto} / {svc}")
        print(f"Duration  : {dur:.3f}s")
        print(f"Bytes     : {ob} -> {rb}")

        if http_info:
            print("--- HTTP (uid match) ---")
            print(f"Host      : {http_info.get('host')}")
            print(f"Method    : {http_info.get('method')}")
            print(f"URI       : {http_info.get('uri')}")
            print(f"Status    : {http_info.get('status_code')}")
            print(f"User-Agent: {http_info.get('user_agent')}")
        else:
            print("--- HTTP ---")
            print("No http match for uid (non-HTTP, encrypted-only, or timing).")
        print("=================\n")
