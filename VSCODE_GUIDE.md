# VSCODE_GUIDE.md — Step-by-Step Setup

Follow these instructions to run **Central System Log Analyzer** perfectly in Visual Studio Code.

---

## 📋 Prerequisites
1. **VS Code** installed.
2. **Python 3.11+** installed.
3. **Node.js 18+** installed.
4. **Ollama** (Optional, for AI insights) installed from [ollama.com](https://ollama.com).

---

## 🚀 Step 1: Open the Project
1. Open VS Code.
2. Click `File > Open Folder...` and select the `central-system-log-analyzer` directory.

## 🚀 Step 2: Backend Setup
1. Open a new terminal in VS Code (`Ctrl + ~` or `Terminal > New Terminal`).
2. Navigate to the backend:
   ```bash
   cd backend
   ```
3. Create a Virtual Environment:
   ```bash
   python -m venv venv
   ```
4. Activate the Virtual Environment:
   - **Mac/Linux**: `source venv/bin/activate`
   - **Windows**: `venv\Scripts\activate`
5. Install Dependencies:
   ```bash
   pip install -r requirements.txt
   ```
6. Start the Server:
   ```bash
   uvicorn app.main:app --port 8000 --reload
   ```
   *The backend is now live at http://localhost:8000*

## 🚀 Step 3: Frontend Setup
1. Open a **second** terminal tab in VS Code.
2. Navigate to the root folder (if not already there).
3. Install Node packages:
   ```bash
   npm install
   ```
4. Start the Development Server:
   ```bash
   npm run dev
   ```
   *The frontend is now live at http://localhost:3000*

## 🚀 Step 4: AI Setup (Optional)
If you want the "AI Insights" feature:
1. Open your terminal (system terminal or another VS Code tab).
2. Run:
   ```bash
   ollama run llama3
   ```
   *Central System Log Analyzer will automatically detect Ollama and start using it for summaries.*

---

## 🛠️ VS Code Tips
- **Extensions**: Install the **"Python"** and **"ESLint"** extensions for the best experience.
- **Debugging**: You can use the "Run and Debug" tab to set breakpoints in `analyze.py`.
- **Prettier**: Use Prettier to keep the `index.css` and `App.jsx` files looking clean.
