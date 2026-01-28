import json
import time
import threading
from pathlib import Path
from collections import deque
import requests

import joblib
import pandas as pd
import numpy as np

PIPE_PATH = "ids_pipeline.joblib"
ZEEK_DIR  = "/Users/cghute/zeek-ids"
CONN_LOG  = f"{ZEEK_DIR}/conn.log"
HTTP_LOG  = f"{ZEEK_DIR}/http.log"

THRESHOLD = 0.5  # tune as needed
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.1:8b"

pipe = joblib.load(PIPE_PATH)

# ---------------- Helpers ----------------
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

# ---------------- Feature mapping: Zeek conn -> UNSW-like model input ----------------
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

# ---------------- HTTP correlation cache (uid -> http info) ----------------
http_by_uid = {}
http_uid_order = deque(maxlen=50000)
http_lock = threading.Lock()

def cache_http(uid: str, info: dict):
    if not uid:
        return
    with http_lock:
        http_by_uid[uid] = info
        http_uid_order.append(uid)
        if len(http_uid_order) == http_uid_order.maxlen:
            for _ in range(1000):
                if not http_uid_order:
                    break
                old = http_uid_order.popleft()
                http_by_uid.pop(old, None)

def http_tailer():
    for line in follow(HTTP_LOG):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # JSON http.log (your current format)
        if line.startswith("{") and line.endswith("}"):
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue

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
            cache_http(uid, info)

threading.Thread(target=http_tailer, daemon=True).start()

# ---------------- LLM (Ollama) triage ----------------
def llm_triage(alert: dict) -> dict:
    """
    Calls local Ollama and asks for SOC triage JSON.
    Returns dict (best-effort). If parsing fails, returns {"raw": "..."}.
    """
    system = (
        "You are a SOC Tier-1 triage assistant. "
        "Be concise, avoid wild speculation. "
        "Return ONLY valid JSON with keys: "
        "summary, severity, likely_category, evidence, recommended_next_steps."
    )

    prompt = f"""{system}

Alert context (JSON):
{json.dumps(alert, indent=2)}
"""

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2
        }
    }

    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=25)
        r.raise_for_status()
        text = r.json().get("response", "").strip()
    except Exception as e:
        return {"summary": "LLM call failed", "error": str(e)}

    # Ollama may return extra text; try to extract JSON
    # Find first '{' and last '}' and parse that region
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start:end+1]
        try:
            return json.loads(candidate)
        except Exception:
            return {"raw": text}

    return {"raw": text}

print("Real-time scoring started.")
print("Watching conn:", CONN_LOG)
print("Watching http:", HTTP_LOG, "(correlate on alerts)")
print("Threshold:", THRESHOLD)
print("LLM:", OLLAMA_MODEL, "via", OLLAMA_URL)

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
    state = evt.get("conn_state", "-")
    dur = safe_float(evt.get("duration"), 0.0)
    ob = safe_int(evt.get("orig_bytes"), 0)
    rb = safe_int(evt.get("resp_bytes"), 0)
    opk = safe_int(evt.get("orig_pkts"), 0)
    rpk = safe_int(evt.get("resp_pkts"), 0)

    # Print scored flow (compact)
    print(f"score={score:.6f} uid={uid} {oh}:{op} -> {rh}:{rp} proto={proto} service={svc} dur={dur:.3f}s bytes={ob}/{rb}")

    if score < THRESHOLD:
        continue

    # Try to fetch correlated HTTP info (wait briefly for timing)
    http_info = None
    for _ in range(3):
        with http_lock:
            http_info = http_by_uid.get(uid)
        if http_info:
            break
        time.sleep(0.25)

    alert = {
        "score": round(score, 6),
        "threshold": THRESHOLD,
        "uid": uid,
        "src": {"ip": oh, "port": op},
        "dst": {"ip": rh, "port": rp},
        "proto": proto,
        "service": svc,
        "conn_state": state,
        "duration_s": round(dur, 3),
        "bytes": {"orig": ob, "resp": rb},
        "pkts": {"orig": opk, "resp": rpk},
        "http": http_info or None,
        "note": "HTTP may be absent for TLS/ssl flows; this is normal."
    }

    print("\n=== IDS ALERT (RAW) ===")
    print(json.dumps(alert, indent=2))
    print("=======================\n")

    triage = llm_triage(alert)
    print("=== LLM TRIAGE (JSON) ===")
    print(json.dumps(triage, indent=2))
    print("=========================\n")
