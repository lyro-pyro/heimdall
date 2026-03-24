# HEIMDALL: AI Secure Data Intelligence Platform

![Heimdall Platform](https://logai-platform-mhbwlfzoe-avula-subhangs-projects.vercel.app/vite.svg)

**HEIMDALL** is a high-performance, retro-futuristic log analysis and threat intelligence platform designed for modern Security Operations Centers (SOCs). Featuring an Evangelion-inspired cyber-aesthetic UI and a blazing-fast FastAPI backend, Heimdall autonomously scans data streams, detects leaked credentials, and correlates suspicious activities into actionable threat intelligence.

## 🚀 The Ultimate Cybersecurity Feature Set

*   **⚡ Real-Time Log Tailing & Scanning**: Stream logs and instantly detect security anomalies with sub-millisecond latency using a deterministic regex ruleset.
*   **🧠 Shannon Entropy Engine**: Identifies highly obfuscated data, base64-encoded strings, and hidden JWT tokens using statistical entropy calculations.
*   **🛡️ Automated MITRE ATT&CK Mapping**: Every detected vulnerability (e.g., SQL Injection, Brute Force, Leaked Tokens) is deterministically mapped to the relevant MITRE Tactics and Techniques (e.g., *T1552: Unsecured Credentials*).
*   **🎯 IOC Extraction Registry**: Automatically surfaces **Indicators of Compromise (IOCs)** such as malicious IPs, exposed tokens, and compromised identities into a unified telemetry panel for one-click SIEM export.
*   **🌌 NERV-Style Retro-Futuristic UI**: A meticulously crafted, high-density dashboard inspired by 90s sci-fi interfaces and technical anime (Evangelion).

## 🛠️ Technology Stack

*   **Frontend**: React (Vite), Vanilla CSS (Custom Design System), Axios
*   **Backend**: Python, FastAPI, Uvicorn, Pydantic
*   **Deployment**: Vercel (Frontend & Serverless Backend)

## 📦 Local Installation

### 1. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Frontend Setup

```bash
npm install
npm run dev
```

Navigate to `http://localhost:3000` to access the Heimdall interface.

## 📡 Usage

1.  Paste raw server logs into the `// DATA_STREAM_BUFFER` or select a test scenario.
2.  Toggle `HEURISTIC_FLAGS` based on the strictness required.
3.  Click `INITIATE SYSTEM SCAN`.
4.  Review the `HEX_DUMP` matrix for threat mappings.
5.  Export the `[ THREAT_INTEL // IOC_REGISTRY ]` to your enterprise firewall or SIEM.

## 📜 License

MIT License. See `LICENSE` for more information.
