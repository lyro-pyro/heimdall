# PROJECT_BREAKDOWN.md

This document provides a comprehensive, file-by-line explanation of the **Central System Log Analyzer** project. It is designed to give you a deep understanding of every component, its importance, and how the code blocks work together to form a secure data intelligence platform.

---

## 🏗️ System Architecture Overview

Central System Log Analyzer follows a modular architecture where each component has a single, well-defined responsibility. The data flow is as follows:
1. **Ingestion**: Raw content is sent to the `/analyze` endpoint.
2. **Parsing**: Content is normalized into a standard string format.
3. **Detection**: Regex-based scanners identify sensitive patterns on each line.
4. **Log Analysis**: Cross-line correlation detects brute-force and IP-based threats.
5. **Risk Scoring**: Findings are weighted and aggregated into a risk score.
6. **Policy Enforcement**: Actions (Mask/Block) are applied based on security rules.
7. **Intelligence**: AI (Ollama) or rule-based templates generate human-readable insights.

---

## 📁 Backend Breakdown (`backend/app/`)

### 1. `api/analyze.py` (The Heart)
This file orchestrates the entire analysis pipeline.
- **`analyze_pipeline` function**: This is the "brain." It sequentially calls the parser, detector, analyzer, and engine services.
- **Importance**: It ensures that data flows correctly between services and that the final response matches the API contract.
- **Key Block**: The `if payload.input_type == 'log'` block enables deep log analysis only when appropriate, saving processing power for simple text.

### 2. `services/detector.py` (The Scanner)
Responsible for finding sensitive patterns within individual lines.
- **`detect` method**: Splits content by `\n` to maintain line number accuracy.
- **Importance**: It's the primary line of defense. Without this, we wouldn't know *where* the leaks are.
- **Key Block**: `_is_duplicate` prevents the same finding type (e.g., two emails) from being reported twice on the same line, preventing noise in the UI.

### 3. `services/log_analyzer.py` (The Auditor)
Handles logic that requires "state" across multiple lines (e.g., brute force).
- **`analyze` method**: Iterates through logs and tracks failed login counts.
- **Importance**: Detects behavioral threats that a simple regex scan would miss.
- **Key Block**: `BRUTE_FORCE_THRESHOLD = 5`. This is the sensitivity dial for attack detection.

### 4. `services/insight_engine.py` (The Intelligence)
Generates the "Summary" and "Insights" sections.
- **`_try_ai_generation`**: Attempting to use Ollama LLM for natural language.
- **Importance**: Makes the technical findings understandable for human security teams.
- **Key Block**: The `prompt` construction. It feeds the findings list into the AI to get a concise JSON summary.

### 5. `utils/patterns.py` (The Knowledge Base)
Contains all the regular expressions and risk mappings.
- **`SENSITIVE_PATTERNS`**: Maps pattern names (e.g., `api_key`) to their regex.
- **`RISK_MAP`**: Defines the "cost" of each finding (e.g., `password: critical`).
- **Importance**: This is where you tune the detection sensitivity. Adding a new regex here immediately enables its detection system-wide.

---

## 📁 Frontend Breakdown (`src/`)

### 1. `App.jsx` (The Shell)
The main React component that manages global state (`result`, `isLoading`, `error`).
- **`handleAnalyze`**: The bridge between the UI and the backend API.
- **Importance**: Coordinates the display of different panels based on the analysis results.

### 2. `components/InputPanel.jsx` (The Gateway)
Handles user input and the 6 built-in test scenarios.
- **`TEST_SCENARIOS`**: A static array of verified security leaks.
- **Importance**: Provides an easy way for users to test the platform without needing their own malicious logs.

### 3. `components/LogViewer.jsx` (The UI Highlighter)
Renders the log content with colored indicators for flagged lines.
- **Importance**: Visually maps the JSON findings back to the original text, making it easy to see exactly where the leak occurred.

### 4. `index.css` (The Aesthetic)
The "Cyber Security" design system.
- **`--font-cyber`**: Uses 'Share Tech Mono' for that terminal look.
- **`.glass-card::before`**: Implements the scanline effect to give it a professional security feel.

---

## 🤖 How AI is Working (Step-by-Step)

The AI integration is handled in `InsightEngine`:

1.  **Context Building**: The system gathers all detected findings (e.g., "Found 1 Password, 2 API Keys").
2.  **Prompting**: It constructs a professional prompt: *"You are a cybersecurity analyst. Here are the findings... generate a summary and 3 insights in JSON format."*
3.  **Local Execution**: It sends this prompt to **Ollama** (running locally on your machine). This ensures your data never leaves your infrastructure, maintaining 100% privacy.
4.  **JSON Parsing**: The system receives the AI response and tries to parse the JSON.
5.  **Fallback**: If Ollama is not installed or the response is invalid, it immediately switches to a **Rule-Based Template** so the user always gets a valid response.

---

## 🌐 Vercel and Deployment

- **`vercel.json`**: Configures Vercel to treat the `api/` folder as Python serverless functions and the rest as a Static React app.
- **Performance**: This allows the platform to scale globally while keeping the backend logic secure.
