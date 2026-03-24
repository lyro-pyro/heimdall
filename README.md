# Central System Log Analyzer

![Central System Log Analyzer Platform](https://logai-platform-mhbwlfzoe-avula-subhangs-projects.vercel.app/vite.svg)

**Central System Log Analyzer** is a high-performance log analysis and threat intelligence platform designed for modern Security Operations Centers (SOCs). Featuring a streamlined UI and a fast FastAPI backend, this analyzer autonomously scans data streams, detects leaked credentials, and correlates suspicious activities into actionable threat intelligence.

## 🚀 Key Features

*   **⚡ Real-Time Log Tailing & Scanning**: Stream logs and instantly detect security anomalies with sub-millisecond latency using a deterministic regex ruleset.
*   **🧠 Shannon Entropy Engine**: Identifies highly obfuscated data, base64-encoded strings, and hidden JWT tokens using statistical entropy calculations.
*   **🛡️ Automated MITRE ATT&CK Mapping**: Every detected vulnerability (e.g., SQL Injection, Brute Force, Leaked Tokens) is deterministically mapped to the relevant MITRE Tactics and Techniques (e.g., *T1552: Unsecured Credentials*).
*   **🎯 IOC Extraction Registry**: Automatically surfaces **Indicators of Compromise (IOCs)** such as malicious IPs, exposed tokens, and compromised identities into a unified telemetry panel for easy SIEM export.
*   **📊 Comprehensive Insights Dashboard**: Provides an immediate overview of total threat volume, critical risk levels, and categorized remediation steps.

## 🛠️ Technology Stack

*   **Frontend**: React (Vite), CSS, Axios
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

Navigate to `http://localhost:3000` to access the interface.

## 📡 Usage

1. Paste raw server logs into the provided text buffer or execute a simulated test payload.
2. Toggle necessary scan flags.
3. Click `INITIATE SYSTEM SCAN`.
4. Review the results matrix for specific threat mappings and risk levels.
5. Export the extracted IOCs directly to your enterprise firewall or SIEM.

## 📜 License

MIT License. See `LICENSE` for more information.
