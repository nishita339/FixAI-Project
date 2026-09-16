# 🔮 FixAI: Intelligent Failure Prediction, Diagnosis & Self-Healing System

[![React](https://img.shields.io/badge/React_19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript_5.9-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python_3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS_4-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![XGBoost](https://img.shields.io/badge/XGBoost-EB5424?style=for-the-badge&logo=xgboost&logoColor=white)](https://xgboost.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

FixAI is an autonomous, AI-driven failure prediction, root-cause diagnosis, guided recovery, and permission-aware self-healing system designed for modern cloud infrastructure, edge devices, and server deployments.

FixAI continuously monitors system telemetry, predicts failures minutes ahead of critical downtime, explains root causes in plain English using SHAP-style attributions, and executes safe, permission-gated recovery playbooks with automated post-fix verification.

---

## 📑 Table of Contents
- [🌟 Key Features](#-key-features)
- [🏗️ System Architecture](#️-system-architecture)
- [📁 Repository Structure](#-repository-structure)
- [🤖 AI & ML Engine](#-ai--ml-engine)
- [🚀 Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [1. Backend Setup (FastAPI)](#1-backend-setup-fastapi)
  - [2. Frontend Setup (FixAI Guardian)](#2-frontend-setup-fixai-guardian)
  - [3. Fault Simulation Script](#3-fault-simulation-script)
- [🛡️ Permission & Safety Architecture](#️-permission--safety-architecture)
- [📊 Datasets Used](#-datasets-used)
- [📜 License](#-license)

---

## 🌟 Key Features

1. **Predictive Failure Detection**
   - **Isolation Forest** unsupervised anomaly detection on multi-metric streams (CPU, RAM, Latency, Disk, Error Rate).
   - **XGBoost Classifier** predicting probability of failure (\text{Failure})$ within a 5-minute lead window.
   - Remaining Useful Life (RUL) estimation using CMAPSS turbine data.

2. **Explainable AI (XAI) & Root Cause Analysis**
   - **SHAP-style Feature Attributions** decomposing anomaly metrics to pinpoint exact failure drivers.
   - **Log Evidence Fusion**: Correlating real-time error logs (e.g., OOMKilled, ConnectionRefused, Timeout) with telemetry spikes.
   - **Plain-English Explanations**: Automated natural language diagnostic reports.

3. **Dual-Mode Recovery**
   - **Manual Guided Mode**: Step-by-step interactive instructions with copyable terminal fixes.
   - **Automated Execution**: One-click execution of allowlisted playbooks.

4. **Permission-Aware Policy Engine**
   - Risk-tiered execution gates (**LOW**, **MEDIUM**, **HIGH**).
   - Low-risk non-destructive actions auto-execute under rate limits.
   - High-risk operations require explicit human authorization.
   - Destructive command blocking (AST-level guardrails).

5. **Closed-Loop Telemetry Validation**
   - Automatic 15-second post-fix soak period.
   - Compares pre-fix vs. post-fix metrics to ensure system health is restored.

---

## 🏗️ System Architecture

`
┌─────────────────┐       ┌──────────────────────┐       ┌─────────────────────┐
│ Live Telemetry  │ ────▶ │  AI Analytics Engine │ ────▶ │   Recovery Engine   │
│ (CPU, RAM, Disk,│       │  - Isolation Forest  │       │  - Policy Gate      │
│  Latency, Logs) │       │  - XGBoost P(Fail)   │       │  - Playbook Run     │
└─────────────────┘       │  - SHAP Attribution  │       │  - Soak Validation  │
                          └──────────────────────┘       └─────────────────────┘
                                     │                              │
                                     ▼                              ▼
                          ┌──────────────────────┐       ┌─────────────────────┐
                          │   XAI Explanation    │       │   Incident Memory   │
                          │   Plain-English RCA  │       │   & Audit Log       │
                          └──────────────────────┘       └─────────────────────┘
`

---

## 📁 Repository Structure

`
FixAI-Project/
├── backend/                  # FastAPI REST API & Database Backend
│   ├── alembic/              # Database migration scripts
│   ├── app/
│   │   ├── api/v1/           # API routes (agent_bridge, playbooks, recovery, incidents)
│   │   ├── models/           # SQLAlchemy database models
│   │   ├── schemas/          # Pydantic schemas
│   │   ├── config.py         # App configuration
│   │   ├── database.py       # DB connection & session management
│   │   └── main.py           # FastAPI application entrypoint
│   └── requirements.txt      # Python dependencies
│
├── fixai-guardian/           # FixAI Guardian Frontend (Dashboard & Agent)
│   ├── src/
│   │   ├── components/       # UI components & FixAI widgets
│   │   ├── convex/           # Convex serverless DB schema & functions
│   │   ├── hooks/            # Agent state machine & custom React hooks
│   │   ├── lib/              # Telemetry simulator, Playbooks & Policy engine
│   │   └── pages/            # Dashboard, Monitor, Recovery, Incidents, etc.
│   ├── package.json          # Node dependencies & scripts
│   └── vite.config.ts        # Vite configuration
│
├── data/                     # Training and benchmark datasets
│   ├── cmapss/               # NASA CMAPSS Turbofan degradation dataset (FD001-FD004)
│   ├── ai4i2020.csv          # AI4I Predictive Maintenance dataset
│   └── BGL_2k.log_structured.csv # BlueGene/L structured log dataset
│
├── scripts/
│   └── simulate_fault.py     # CLI tool to simulate CPU, RAM, Disk & Network faults
│
├── .gitignore                # Git ignore configuration
└── README.md                 # Project documentation
`

---

## 🤖 AI & ML Engine

| Component | Model / Algorithm | Purpose |
| :--- | :--- | :--- |
| **Anomaly Scoring** | Isolation Forest | Unsupervised deviation detection from normal operating baselines |
| **Failure Prediction** | XGBoost Classifier | Binary & Multi-class failure prediction (\text{failure})$ |
| **Remaining Useful Life** | Gradient Boosting Regressor | Predicts remaining operation cycles / time to critical failure |
| **Feature Importance** | SHAP Decomposition | Ranks top contributing metrics causing the anomaly |
| **Log Intelligence** | Regex & Pattern Matcher | Extracts structured error signatures from raw logs |

---

## 🚀 Getting Started

### Prerequisites
- **Node.js** (v18+) or **Bun**
- **Python** (v3.10+)
- **Git**

---

### 1. Backend Setup (FastAPI)

`ash
# Navigate to backend directory
cd backend

# Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
# source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Run migrations (SQLite default)
alembic upgrade head

# Start FastAPI server
uvicorn app.main:app --reload --port 8000
`
Backend API will be available at http://localhost:8000 (Swagger UI at http://localhost:8000/docs).

---

### 2. Frontend Setup (FixAI Guardian)

`ash
# Navigate to frontend directory
cd fixai-guardian

# Install dependencies
npm install
# or: bun install

# Start Vite development server
npm run dev
# or: bun run dev
`
Open http://localhost:5173 in your browser to access the dashboard.

---

### 3. Fault Simulation Script

You can inject real, safe, and self-terminating system stresses to test detection and self-healing:

`ash
# Inject CPU stress (e.g. 60 seconds)
python scripts/simulate_fault.py --fault cpu --duration 60

# Inject Memory exhaustion simulation
python scripts/simulate_fault.py --fault memory --duration 60

# Inject Disk space fill test (automatically cleaned after test)
python scripts/simulate_fault.py --fault disk --duration 30
`

---

## 🛡️ Permission & Safety Architecture

| Risk Tier | Playbook Examples | Authorization Required | Automated Execution |
| :--- | :--- | :--- | :--- |
| **🟢 LOW** | Cache flush, service soft restart, worker thread recycling | Auto-approved | ✅ Yes (Max 3/day) |
| **🟡 MEDIUM** | Container recreate, network route flush, connection pool reset | User Confirmation | ⚠️ User approved |
| **🔴 HIGH** | Database failover, schema rollback, disk volume repartitioning | Manual Intervention | ❌ Blocked by default |

---

## 📊 Datasets Used

- **NASA CMAPSS Dataset**: Turbofan engine degradation simulation for Remaining Useful Life (RUL) estimation.
- **AI4I 2020 Predictive Maintenance**: Synthetic maintenance dataset reflecting real-world industrial machine failures.
- **BGL (BlueGene/L) Log Dataset**: Supercomputer log data for log anomaly correlation and failure signature matching.

---

## 📜 License

This project is licensed under the **MIT License**.
