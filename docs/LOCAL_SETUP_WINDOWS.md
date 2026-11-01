# FixAI Local Windows Setup & Operations Guide

This guide provides end-to-end instructions for installing, configuring, running, and verifying the complete **FixAI** system on a local Windows machine (Windows 10 / Windows 11 / Windows Server).

---

## 1. System Requirements & Prerequisites

Ensure the following runtimes and tools are installed:
- **Operating System**: Windows 10 (64-bit) / Windows 11 / Windows Server 2019+
- **Python**: Version 3.10 to 3.13 (64-bit) with `pip`
- **Node.js**: Version 18.x, 20.x, or 22.x with `npm` (v10+)
- **PowerShell**: Version 5.1 or PowerShell 7 (Run as Administrator for service installation)
- **Git**: Installed and available in `PATH`

---

## 2. Directory Structure Overview

The project is structured into three primary directories:
```text
FixAI-Project/
├── backend/                  # FastAPI backend server & SQLite database
│   ├── app/                  # Application code, routers, database models
│   ├── test_suite.py         # 26-test integration suite
│   └── requirements.txt      # Backend Python dependencies
├── fixai-guardian/           # React 18 + Vite frontend & Local Python Agent
│   ├── src/                  # React dashboard components, pages, hooks
│   ├── local_agent/          # Autonomous Python telemetry & EDR agent
│   │   ├── ai_engine/        # EdgeAIEngine (XGBoost, Isolation Forest, SHAP)
│   │   ├── security/         # File monitor, EDR rules, quarantine vault
│   │   ├── evaluate.py       # ML evaluation script
│   │   └── tests/            # 262-test agent pytest suite
│   └── package.json          # Frontend dependencies
├── data/                     # UCI AI4I, NASA C-MAPSS, and host telemetry datasets
├── docs/                     # Technical, model, test, and setup documentation
├── service.py                # Windows Service wrapper script
└── install_service.ps1       # Automated Windows Service installer
```

---

## 3. Step 1: Setting Up the Backend Server

### 3.1 Navigate to Backend Directory
Open PowerShell or Command Prompt:
```powershell
cd "c:\Users\Monika\OneDrive\Desktop\FixAI-Project (2)\FixAI-Project\backend"
```

### 3.2 Install Backend Dependencies
Install the required Python packages:
```powershell
pip install fastapi uvicorn pydantic pydantic-settings sqlalchemy aiosqlite httpx pyjwt cryptography psutil scikit-learn xgboost shap joblib
```

### 3.3 Configure Environment Variables
Create or verify `backend/.env`:
```env
FIXAI_ENV=development
API_HOST=0.0.0.0
API_PORT=8000
DATABASE_URL=sqlite+aiosqlite:///./fixai.db
JWT_SECRET=fixai-development-secret-key-32chars
OTP_EXPIRE_SECONDS=300
CORS_ORIGINS=["http://localhost:8080","http://localhost:5173","http://localhost:3000"]
```

### 3.4 Verify Backend Integration Tests
Execute the comprehensive 26-test integration suite:
```powershell
python test_suite.py
```
*Expected Output: `All 26/26 Integration Tests PASSED with ZERO ERRORS!`*

### 3.5 Launch the Backend Server
Start the Uvicorn ASGI server with hot-reload enabled:
```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
The backend is now accessible at:
- **API Root**: `http://localhost:8000/`
- **Health Check**: `http://localhost:8000/health`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **Live Hardware Telemetry WebSocket**: `ws://localhost:8000/ws/telemetry`

---

## 4. Step 2: Setting Up the FixAI Guardian Frontend

### 4.1 Navigate to Frontend Directory
Open a second PowerShell window:
```powershell
cd "c:\Users\Monika\OneDrive\Desktop\FixAI-Project (2)\FixAI-Project\fixai-guardian"
```

### 4.2 Install Dependencies
Install npm packages:
```powershell
npm install
```

### 4.3 Configure Frontend Environment
Ensure `.env` in `fixai-guardian/` contains the backend endpoints:
```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws/telemetry
```

### 4.4 Build & Validate TypeScript
Verify that the TypeScript compiler and Vite bundling succeed without errors:
```powershell
npm run build
```
*Expected Output: `✓ built in 10-12s with 0 errors`*

### 4.5 Start the Development Server
Launch the Vite development server:
```powershell
npm run dev
```
Open your browser and navigate to:
- **Dashboard URL**: `http://localhost:8080` (or `http://localhost:5173`)

---

## 5. Step 3: Running the Local Telemetry Agent

The Local Agent monitors the physical computer hardware, performs real-time edge inference, and streams telemetry to the backend.

### 5.1 Navigate to Local Agent Directory
Open a third PowerShell window:
```powershell
cd "c:\Users\Monika\OneDrive\Desktop\FixAI-Project (2)\FixAI-Project\fixai-guardian\local_agent"
```

### 5.2 Validate Machine Learning Models
Run the multi-model validation script against held-out splits:
```powershell
python evaluate.py
```
*Expected Output: Evaluates AI4I XGBoost (F1: 0.773, ROC-AUC: 0.978), NASA C-MAPSS (RMSE: 17.559), and real telemetry baseline.*

### 5.3 Run Agent Test Suite
Run the 262 unit and EDR tests:
```powershell
python -m pytest tests/ -q
```
*Expected Output: `262 passed in ~80-90s`*

### 5.4 Launch Telemetry Daemon
Run the interactive agent daemon:
```powershell
python main.py
```
The agent will:
1. Initialize `EdgeAIEngine` with pre-trained XGBoost and Isolation Forest models.
2. Begin sampling real CPU per-core utilization, RAM breakdown, disk space, and socket RTT latency.
3. Transmit telemetry to `http://localhost:8000/api/v1/agent/ingest`.
4. Fall back to local SQLite buffer (`offline_telemetry.db`) if the backend is temporarily stopped.

---

## 6. Step 4: Installing as a Persistent Windows Service (Optional)

To run the FixAI Agent automatically on Windows startup without keeping a console window open:

### 6.1 Open Elevated PowerShell
Right-click **Windows Start Menu** → Select **PowerShell (Administrator)**.

### 6.2 Execute Service Installer
Navigate to the project root and run:
```powershell
cd "c:\Users\Monika\OneDrive\Desktop\FixAI-Project (2)\FixAI-Project"
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\install_service.ps1
```

### 6.3 Manage the Service
You can manage the service using standard Windows Service commands:
```powershell
# Check status
Get-Service FixAIGuardianAgent

# Stop the service
Stop-Service FixAIGuardianAgent

# Restart the service
Restart-Service FixAIGuardianAgent
```

---

## 7. Troubleshooting & FAQs

### Q: Why does the Dashboard display `Temperature: N/A`?
**A:** On standard consumer laptops and Windows desktop hardware without elevated ACPI thermal drivers (e.g. OpenHardwareMonitor or manufacturer WMI providers), Windows restricts kernel thermal query APIs for unprivileged users. FixAI **strictly adheres to honest reporting**: it will display `temp: null, temp_available: false` rather than inventing a fabricated temperature.

### Q: How do I test the self-healing playbook without damaging my system?
**A:** Use the safe, non-destructive playbooks:
- `clean_hosts_file`: Verifies `C:\Windows\System32\drivers\etc\hosts` and flushes DNS cache via `ipconfig /flushdns`.
- `remediate_brute_force`: Applies a targeted host firewall inbound block rule and logs the incident.
- `kill_runaway_process`: Safely tests process termination against benign worker PIDs while protecting critical OS processes (PIDs 0, 4, etc.).

### Q: What happens if the backend is stopped while the agent is running?
**A:** The agent automatically switches to **Offline Buffering Mode**. All metrics are recorded locally in `offline_telemetry.db`. Once the backend is restarted, the agent flushes the buffered readings in order via `/api/v1/agent/ingest-batch`.
