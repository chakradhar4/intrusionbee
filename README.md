
# 🛡️ Agentic AI–Powered Intrusion Detection System (IDS)

This project demonstrates an **Agentic AI cybersecurity pipeline** that combines:

- **Zeek** for real-time network telemetry  
- **Machine Learning** for anomaly / intrusion risk scoring  
- **Local LLM (Ollama + Llama 3.1)** for autonomous SOC triage and decision support  

The system runs **fully locally** and performs **real-time detection, enrichment, reasoning, and recommendations**.

---

## 🔍 High-Level Architecture

```
Network Traffic
      ↓
   Zeek Sensor
 (conn.log, http.log)
      ↓
 Feature Mapping
      ↓
 ML Risk Scoring
 (UNSW-NB15 model)
      ↓
 Alert Trigger
      ↓
 Context Enrichment
 (HTTP correlation)
      ↓
 LLM Agent (Ollama)
      ↓
 SOC-style Triage Output
```

---

## 🚀 Capabilities

### What the system does
- ✅ Real-time network flow scoring
- ✅ Binary intrusion detection (benign vs suspicious)
- ✅ HTTP request correlation (Host / URI / Method / User-Agent)
- ✅ Autonomous SOC triage using a local LLM
- ✅ Structured agent output (severity, evidence, next steps)
- ✅ Runs fully offline (no cloud dependency)

### What the system does NOT claim (by design)
- ❌ Perfect detection accuracy (model is UNSW-trained, not Zeek-native)
- ❌ Payload inspection of encrypted HTTPS
- ❌ Final blocking decisions without human review

This is **decision-support AI**, not an auto-firewall.

---

## 📦 Components

### 1. Zeek (Telemetry Layer)
- Captures live traffic
- Produces:
  - `conn.log` → network flows
  - `http.log` → HTTP request metadata (when visible)

Zeek is configured to output **JSON logs**.

---

### 2. Machine Learning Model
- Trained on **UNSW-NB15** dataset
- Binary classifier:
  - `0` → normal
  - `1` → suspicious
- Outputs a **risk probability score**
- Used in real time on Zeek flows

Files:
- `baseline_model.py`
- `ids_pipeline.joblib`

---

### 3. Real-Time Scoring Engine
- Tails `conn.log`
- Maps Zeek fields to model features
- Scores each flow in real time
- Applies configurable threshold

Files:
- `realtime_zeek_score.py`
- `realtime_zeek_score_llm.py`

---

### 4. HTTP Correlation
- Uses Zeek `uid` to correlate:
  - `conn.log` ↔ `http.log`
- Enriches alerts with:
  - Host
  - URI
  - HTTP method
  - User-Agent
  - Status code

Only applied **when an alert fires**.

---

### 5. Local LLM Agent (Ollama)
- Uses **Llama 3.1 (8B)** via Ollama
- Runs fully locally
- Performs:
  - Alert summarization
  - Severity classification
  - Likely intent reasoning
  - Recommended next steps

---

## 🤖 Agentic AI Behavior

For each alert, the system produces:

### Raw Alert Context
```json
{
  "score": 0.72,
  "src": "192.168.1.8",
  "dst": "45.60.49.15",
  "service": "http",
  "bytes": "500/4000",
  "http": {
    "host": "example.com",
    "uri": "/login",
    "method": "POST"
  }
}
```

### LLM Agent Output
```json
{
  "summary": "Suspicious outbound HTTP POST to external host",
  "severity": "medium",
  "likely_category": "web reconnaissance or credential activity",
  "evidence": [
    "Outbound POST request",
    "External destination",
    "Unusual byte ratio"
  ],
  "recommended_next_steps": [
    "Review repeated requests from same source",
    "Check destination domain reputation",
    "Inspect host for browser extensions or scripts"
  ]
}
```

---

## 🛠️ Setup Summary

### Install dependencies
```bash
brew install zeek ollama
ollama pull llama3.1:8b
```

### Start Ollama
```bash
OLLAMA_FLASH_ATTENTION=1 OLLAMA_KV_CACHE_TYPE="q8_0" ollama serve
```

### Run Zeek (JSON logs)
```bash
cd /Users/cghute/zeek-ids
sudo zeek -i en0 LogAscii::use_json=T
```

### Run IDS + Agent
```bash
python realtime_zeek_score_llm.py
```

---

## 🎯 Intended Demo Scenario

1. Start Zeek + IDS agent  
2. Generate HTTP traffic:
   ```bash
   curl http://example.com/login
   ```
3. Alert fires
4. LLM agent produces SOC triage
5. Analyst reviews and decides

---

## 📌 Status

**Working prototype** suitable for:
- Agentic AI demonstrations
- Security architecture discussions
- Applied AI showcases
