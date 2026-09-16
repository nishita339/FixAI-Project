<div align="center">

# 🔮 FixAI
### Autonomous AI-Driven Failure Prediction, Root-Cause Diagnosis & Permission-Aware Self-Healing System

[![React](https://img.shields.io/badge/React_19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript_5.9-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python_3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-EB5424?style=for-the-badge&logo=xgboost&logoColor=white)](https://xgboost.readthedocs.io/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS_4-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Convex](https://img.shields.io/badge/Convex_DB-E85D75?style=for-the-badge&logo=convex&logoColor=white)](https://convex.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

<p align="center">
  <b>FixAI detects system degradation early, pinpoints root causes with Explainable AI (XAI), and autonomously heals infrastructure, containers, services, and host hardware before catastrophic downtime occurs.</b>
</p>

[Key Features](#-key-features) • [System Architecture](#-system-architecture) • [AI & ML Pipelines](#-ai--ml-methodology) • [Laptop Doctor](#-laptop-doctor--endpoint-diagnostics) • [Playbooks & Safety](#-recovery-playbooks--safety-guardrails) • [Quick Start](#-quick-start-guide) • [API Reference](#-api-endpoints-reference)

</div>

---

## 📖 Overview

Modern cloud platforms, microservices, and host systems suffer from prolonged downtime due to **reactive alerting** (alerting only *after* a crash happens) and **manual diagnosis** (engineers digging through logs at 3 AM).

**FixAI** transforms operations from **reactive firefighting** to **proactive, automated self-healing**:

`
Live Telemetry Stream ──▶ Unsupervised Anomaly Detection (Isolation Forest)
                      ──▶ Failure Probability Estimation (XGBoost Classifier)
                      ──▶ Root Cause Attribution (SHAP TreeExplainer)
                      ──▶ Natural Language Diagnosis (NLG Engine)
                      ──▶ Permission-Gated Execution (LOW / MEDIUM / HIGH Gates)
                      ──▶ Allowlisted Playbook Execution (Local / Cloud Agent)
                      ──▶ 15-Second Post-Fix Telemetry Soak Verification
                      ──▶ Incident Memory Update & Immutable Audit Trail
`

---

## 🌟 Key Features

### 1. 🔮 Predictive Failure Detection
* **Unsupervised Anomaly Scoring:** Uses an Isolation Forest algorithm trained on normalized 5-dimensional feature vectors (CPU, RAM, Disk, Latency, Error Rate) to output continuous anomaly scores $\in [0, 1]$.
* **Probabilistic Failure Prediction:** Employs an XGBoost Classifier with cost-sensitive weighting (FP: 10, FN: 500) to forecast failure probabilities (\text{Failure})$ up to 5 minutes before system crash.
* **Remaining Useful Life (RUL):** Uses Gradient Boosted Regression trained on the NASA CMAPSS dataset to calculate operational degradation cycles remaining.

### 2. 🧠 Explainable AI (XAI) & Root Cause Analysis
* **SHAP Feature Attributions:** Exact decomposition of decision weights showing which metric contributed most to the anomaly.
* **Log Evidence Fusion:** Intersects metric spikes with error log signatures (e.g., OOMKilled, ConnectionRefused, Timeout, Kernel Panic).
* **Plain-English Explanations:** Automated Natural Language Generation (NLG) converting complex telemetry vectors into concise diagnostic reports.

### 3. 🩺 "Laptop Doctor" Real Hardware Diagnostics
* **Live ACPI & Core Temperature Sensing:** Real hardware stats for CPU core temperature, battery health, and AC charging status.
* **BSOD Crash Dump Analysis:** Automatically detects and inspects Windows Minidump files (C:\Windows\Minidump\*.dmp).
* **Windows Package Manager (winget) Scanner:** Discovers outdated packages, cross-references CVE vulnerability notes, and provides 1-click silent security updates.
* **Runaway Process Killer:** Real-time process inspection with single-click termination of orphan/high-consumption PIDs.

### 4. 🛡️ Dual-Mode Recovery & Safety Guardrails
* **Manual Guided Mode:** Step-by-step interactive instructions with copyable terminal commands for manual SRE intervention.
* **Automated Agentic Mode:** Autonomous dispatch of pre-audited recovery playbooks.
* **Closed-Loop Soak Validation:** Automatically enforces a 15-second post-fix soak period to verify that telemetry metrics return to safe baselines.

---

## 🏗️ System Architecture

`
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   FixAI Ecosystem                                      │
└────────────────────────────────────────────────────────────────────────────────────────┘
                                           │
         ┌─────────────────────────────────┼─────────────────────────────────┐
         ▼                                 ▼                                 ▼
┌──────────────────┐             ┌──────────────────┐             ┌──────────────────┐
│  React Frontend  │             │ FastAPI Backend  │             │   Local Agent    │
│ (FixAI Guardian) │             │ (REST / SQLite)  │             │  (Edge Daemon)   │
│                  │             │                  │             │                  │
│ • Dashboard      │ ◀─────────▶ │ • REST API v1    │ ◀─────────▶ │ • psutil Sensing │
│ • Monitor (Live) │   HTTP /    │ • SQLAlchemy DB  │   REST /    │ • Edge Inference │
│ • Incidents/RCA  │  WebSockets │ • Alembic Schema │   HTTP-Key  │ • Playbook Exec  │
│ • Laptop Doctor  │             │ • Playbook Engine│             │ • Desktop Toast  │
│ • Recovery Mode  │             │ • Safety Filters │             │ • Winget Patch   │
└──────────────────┘             └──────────────────┘             └──────────────────┘
         │                                 │                                 │
         └─────────────────────────────────┼─────────────────────────────────┘
                                           ▼
                       ┌───────────────────────────────────────┐
                       │           AI / ML Core Engine         │
                       │                                       │
                       │ • Isolation Forest (Anomaly Scoring)  │
                       │ • XGBoost Classifier (Failure Prob)   │
                       │ • SHAP TreeExplainer (Feature RCA)    │
                       │ • CMAPSS RUL Estimator (Degradation)  │
                       └───────────────────────────────────────┘
`

---

## 📁 Repository Structure

`
FixAI-Project/
├── backend/                             # FastAPI REST API & Database Backend
│   ├── alembic/                         # Database schema migrations & seeds
│   │   └── versions/                    # Initial schema & playbook seed tables
│   ├── app/
│   │   ├── api/v1/                      # API Endpoints
│   │   │   ├── agent_bridge.py          # Telemetry ingest, live hardware, diagnostics & winget
│   │   │   ├── playbooks.py             # Playbook catalog & parameter specifications
│   │   │   └── recovery.py              # Auto-fix execution, audit trail & soak verification
│   │   ├── models/                      # SQLAlchemy ORM Models
│   │   │   ├── audit.py                 # Immutable audit logs
│   │   │   ├── device.py                # Device registration & agent state
│   │   │   ├── incident.py              # Incidents, SHAP values, status transitions
│   │   │   ├── playbook.py              # Recovery playbooks registry
│   │   │   ├── telemetry.py             # Historical time-series telemetry samples
│   │   │   └── user.py                  # User authentication & roles
│   │   ├── schemas/                     # Pydantic validation schemas
│   │   │   └── agent.py                 # Telemetry ingestion, resolution & claim payloads
│   │   ├── config.py                    # App settings & environment parameters
│   │   ├── database.py                  # Async SQLAlchemy session engine
│   │   └── main.py                      # FastAPI application entrypoint & CORS setup
│   ├── requirements.txt                 # Backend Python dependencies
│   └── fixai.db                         # SQLite local database
│
├── fixai-guardian/                      # FixAI Guardian Frontend (React + Vite)
│   ├── local_agent/                     # Edge Agent Daemon & ML Inference Engine
│   │   ├── ai_engine/                   # Machine learning core
│   │   │   ├── inference.py             # EdgeAIEngine with SHAP TreeExplainer
│   │   │   ├── train.py                 # AI4I & synthetic model training pipeline
│   │   │   ├── train_rul.py             # NASA CMAPSS RUL training script
│   │   │   └── train_telemetry.py       # Custom telemetry adaptation trainer
│   │   ├── models/                      # Pre-trained .joblib model artifacts & scalers
│   │   ├── recovery/                    # Local playbook executor
│   │   │   └── executor.py              # Safe OS process execution & verification
│   │   ├── evaluate.py                  # Model evaluation & performance benchmarking
│   │   ├── main.py                      # Edge daemon loop (psutil + desktop notifications)
│   │   └── requirements.txt             # Agent Python requirements
│   ├── src/
│   │   ├── components/
│   │   │   ├── fixai/                   # Custom domain components
│   │   │   │   ├── AppShell.tsx         # Dashboard sidebar & top navigation
│   │   │   │   ├── CausalGraphView.tsx  # Causal dependency & DAG failure graph
│   │   │   │   ├── MetricCard.tsx       # Live telemetry metric cards
│   │   │   │   ├── PipelineFlow.tsx     # 8-stage self-healing lifecycle widget
│   │   │   │   ├── RiskGauge.tsx        # Animated SVG failure risk gauge
│   │   │   │   └── badges.tsx           # Status, severity & risk-tier badges
│   │   │   └── ui/                      # shadcn/ui components (Radix primitives)
│   │   ├── convex/                      # Convex serverless backend schema & queries
│   │   ├── hooks/                       # React state hooks & agent context
│   │   │   ├── use-fixai-agent.ts       # Closed-loop self-healing state machine
│   │   │   └── use-auth.ts              # Authentication state management
│   │   ├── lib/                         # Client utilities, playbooks & policy rules
│   │   └── pages/                       # Application Views
│   │       ├── Dashboard.tsx            # Main executive dashboard
│   │       ├── Monitor.tsx              # Live charts & interactive fault injector
│   │       ├── Incidents.tsx            # Incident list & SHAP root-cause drawer
│   │       ├── LaptopDoctor.tsx         # Deep host diagnostics & software updater
│   │       ├── Recovery.tsx             # Dual-mode manual/automated recovery
│   │       ├── History.tsx              # Audit trail & incident resolution logs
│   │       ├── Permissions.tsx          # Risk-tier matrix policy editor
│   │       ├── Landing.tsx              # Public product landing page
│   │       └── Auth.tsx                 # Login & user registration
│   ├── package.json                     # Frontend npm packages
│   └── vite.config.ts                   # Vite build configuration
│
├── data/                                # Datasets used for training & evaluation
│   ├── cmapss/                          # NASA Turbofan degradation dataset (FD001-FD004)
│   ├── ai4i2020.csv                     # AI4I Predictive Maintenance dataset
│   ├── BGL_2k.log_structured.csv        # BlueGene/L structured log dataset
│   └── telemetry.jsonl                  # Sample streaming telemetry logs
│
├── scripts/
│   └── simulate_fault.py                # Safe CLI tool to simulate CPU, RAM & disk faults
│
├── .gitignore                           # Git ignore definitions
└── README.md                            # Complete system documentation
`

---

## 🔬 AI & ML Methodology

FixAI combines multiple specialized machine learning models for holistic fault detection and diagnosis:

`
Telemetry Vector [CPU, RAM, Latency, ErrorRate, Disk]
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
┌──────────────────┐       ┌──────────────────┐
│ Isolation Forest │       │ XGBoost Model    │
│ Anomaly: [0, 1]  │       │ P(Fail): [0, 1]  │
└──────────────────┘       └──────────────────┘
         │                           │
         └─────────────┬─────────────┘
                       ▼
            ┌──────────────────────┐
            │ SHAP TreeExplainer   │ ──▶ Attributions per Metric
            └──────────────────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │ Template NLG Engine  │ ──▶ Plain-English Diagnostic Summary
            └──────────────────────┘
`

| Task | Algorithm | Features | Output / Goal |
| :--- | :--- | :--- | :--- |
| **Anomaly Scoring** | IsolationForest(n_estimators=100) | cpu, am, latency, error_rate, disk | Normalized anomaly score $\in [0, 1]$ |
| **Failure Prediction** | XGBClassifier(max_depth=4, n_est=150) | Scaled 5-metric vector + moving averages | (\text{Failure})$ in next 5 minutes |
| **Root Cause Analysis** | shap.TreeExplainer(model) | Fitted trees & scaled deviations | Signed feature attribution weights |
| **Remaining Useful Life** | GradientBoostingRegressor | CMAPSS 21 sensor measurements | Predicted operational cycles to failure |
| **Log Diagnosis** | Regex & Pattern Signature Matcher | Host system & container logs | Error classification (OOM, Socket, Disk) |

---

## 🩺 Laptop Doctor & Endpoint Diagnostics

The **Laptop Doctor** (/dashboard/laptop-doctor) module extends FixAI beyond cloud containers into real host hardware management:

`
┌───────────────────────────────────────────────────────────────────────────┐
│                           Laptop Doctor Console                           │
├───────────────────┬───────────────────┬───────────────────┬───────────────┤
│ Core Temp: 48.5°C │ Battery: 89% (AC) │ SSD Free: 220.4GB │ BSOD Dumps: 0 │
└───────────────────┴───────────────────┴───────────────────┴───────────────┘
`

* **Live Hardware Sensors:** Direct reading of CPU temperature, battery discharge rate, and SSD health.
* **Top Process Monitor:** Real-time RAM/CPU consumer table with one-click PID termination.
* **Windows Package Manager (winget) Scanner:** Identifies outdated runtimes (Node.js, Git, VC++ Redistributable, Docker Desktop) and executes safe silent upgrades.
* **Windows Services Guard:** Monitors critical system services (Audiosrv, WlanSvc, wuauserv, BITS) and auto-heals stopped services.

---

## 🛡️ Recovery Playbooks & Safety Guardrails

FixAI maintains a strict **zero-unauthorized-action** guarantee using a multi-tiered safety architecture:

### Risk-Tier Matrix

| Risk Tier | Example Playbooks | Execution Policy | Auto-Approval Limit |
| :--- | :--- | :--- | :--- |
| **🟢 LOW** | lush_cache, estart_worker, cool_down_cpu, optimize_storage_trim, eset_network_adapter | Autonomous execution | Max 3 executions / day |
| **🟡 MEDIUM** | estart_container, scale_instances, ix_windows_update, epair_system_files | Requires operator 1-click confirmation | Operator gated |
| **🔴 HIGH** | db_maintenance, schema_rollback, disk_repartition | Recommendation only (Manual execution) | Hard-blocked by policy |

### Non-Negotiable Safety Rules:
1. **Allowlisted Playbooks Only:** The execution engine only invokes audited playbook identifiers (playbook_id) with typed parameters—raw arbitrary shell strings are rejected.
2. **Static AST Guard:** Strings containing destructive patterns (m -rf, DROP TABLE, eval(, chmod 777, mkfs) are intercepted and blocked at the API level.
3. **Post-Fix Soak Validation:** Every remediation initiates an automated 15-second metric soak. If telemetry does not normalize, the incident is flagged for manual escalation.
4. **Immutable Audit Trail:** Every decision, trigger, and output is permanently logged in the SQLite / PostgreSQL database.

---

## 🚀 Quick Start Guide

### Prerequisites
* **Node.js** (v18+) or **Bun**
* **Python** (v3.10+)
* **Git**

---

### Step 1: Clone the Repository
`ash
git clone https://github.com/nishita339/FixAI-Project.git
cd FixAI-Project
`

---

### Step 2: Set Up & Run the FastAPI Backend
`ash
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment:
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
uvicorn app.main:app --reload --port 8000
`
Backend API will be live at http://localhost:8000  
Swagger API Docs available at http://localhost:8000/docs

---

### Step 3: Set Up & Run the Frontend (FixAI Guardian)
Open a new terminal window:
`ash
cd fixai-guardian

# Install dependencies
npm install
# or: bun install

# Start development server
npm run dev
# or: bun run dev
`
Open http://localhost:5173 in your browser.

---

### Step 4: Run the Local Agent Daemon (Optional)
To stream real live hardware metrics from your laptop to the dashboard:
`ash
cd fixai-guardian/local_agent

# Install agent dependencies
pip install -r requirements.txt

# Run the agent daemon
python main.py
`

---

### Step 5: Test Fault Simulation
Inject safe, self-terminating faults to watch the self-healing loop in action:
`ash
# Inject CPU spike for 60 seconds
python scripts/simulate_fault.py --fault cpu --duration 60

# Inject Memory leak simulation
python scripts/simulate_fault.py --fault memory --duration 60

# Inject Disk fill test
python scripts/simulate_fault.py --fault disk --duration 30
`

---

## 🔌 API Endpoints Reference

### Agent Bridge Endpoints (/api/v1/agent)
| Method | Endpoint | Description | Auth |
| :--- | :--- | :--- | :--- |
| POST | /api/v1/agent/ingest | Ingests telemetry, ML verdicts, and SHAP weights | x-device-key |
| GET | /api/v1/agent/live-telemetry | Returns real-time host hardware metrics via psutil | Public / Dev |
| GET | /api/v1/agent/system-diagnostics | Returns deep OS, service, battery & BSOD checks | Public / Dev |
| GET | /api/v1/agent/software-updates | Scans host system for outdated packages (winget) | Public / Dev |
| POST | /api/v1/agent/update-software | Dispatches silent update for a target package | Public / Dev |
| GET | /api/v1/agent/pending-actions | Returns pending recovery actions for device | x-device-key |
| POST | /api/v1/agent/claim-action | Claims an action to prevent duplicate execution | x-device-key |
| POST | /api/v1/agent/resolve | Records incident resolution after soak test | x-device-key |

### Recovery Endpoints (/api/v1/recovery)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| POST | /api/v1/recovery/request-auto-fix | Queues a playbook with AST safety validation |
| POST | /api/v1/recovery/execute-live | Executes real OS repair commands and logs resolution |
| GET | /api/v1/recovery/status/{id} | Polls the live execution state of an incident |
| GET | /api/v1/recovery/incidents | Lists historical and active incidents |
| GET | /api/v1/recovery/audit-logs | Fetches the complete immutable audit trail |

### Playbook Endpoints (/api/v1/playbooks)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| GET | /api/v1/playbooks | Lists all 20+ allowlisted playbooks with risk tiers |
| GET | /api/v1/playbooks/{id} | Retrieves playbook execution parameters and description |

---

## 📊 Benchmark Targets vs. Traditional Alerting

| Metric | Traditional Monitoring (e.g. Nagios/CloudWatch) | FixAI Self-Healing Engine |
| :--- | :--- | :--- |
| **Mean Time to Detect (MTTD)** | ~ 5.0 minutes (Reactive threshold alerts) | **< 8 seconds** (Proactive anomaly score) |
| **Mean Time to Recover (MTTR)**| ~ 25.0 minutes (Manual triage + fix) | **< 15 seconds** (Autonomous playbook) |
| **False Positive Rate** | 18.4% | **< 2.8%** (Cost-sensitive XGBoost) |
| **Root Cause Discovery** | Manual log searching | **Instant** (SHAP feature attribution) |
| **Safety Verification** | Manual verification | **100% Automated** (15s soak test) |
| **Destructive Command Risk** | Human error potential | **0%** (AST + allowlist validation) |

---

## 📚 Datasets & Citations

1. **NASA CMAPSS Dataset**: Turbofan Engine Degradation Simulation Dataset (*Saxena and Goebel, NASA Ames Prognostics Data Repository*).
2. **AI4I 2020 Predictive Maintenance Dataset**: Synthetic dataset reflecting real-world industrial machine health (*Dua, D. and Graff, C., UCI Machine Learning Repository*).
3. **BGL (BlueGene/L) Log Dataset**: Supercomputer log dataset collected by Lawrence Livermore National Laboratory (LLNL).

---

## 👥 Authors & Acknowledgments

* **Project**: AI-Driven Intelligent Failure Prediction, Diagnosis, Guided Recovery & Permission-Aware Self-Healing System
* **Author**: Nishita Singh ([@nishita339](https://github.com/nishita339))
* **Repository**: [https://github.com/nishita339/FixAI-Project](https://github.com/nishita339/FixAI-Project)

---

## 📜 License

This project is open-source software licensed under the **[MIT License](LICENSE)**.
