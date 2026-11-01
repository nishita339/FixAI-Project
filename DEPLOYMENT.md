# 🚀 FixAI Cloud Deployment Guide

This guide details how to deploy FixAI to production in under 5 minutes using the recommended cloud hosting stack:

- **Frontend Dashboard:** Deployed on **Vercel** (Global Edge CDN, Free)
- **Backend API & WebSockets:** Deployed on **Render** or **Railway** (Python FastAPI Server, Free Tier Available)
- **Local Endpoint Agent:** Runs locally on your workstation/laptop to harvest sensors and security events, streaming them live to your deployed cloud backend.

---

## 📋 Architecture Overview

```
┌─────────────────────────────────┐       WebSocket / REST       ┌────────────────────────────────┐
│   FixAI Frontend (Vercel)       │ ◄──────────────────────────► │    FixAI Backend (Render)      │
│   https://<your-app>.vercel.app │                              │   https://<your-api>.onrender  │
└─────────────────────────────────┘                              └────────────────────────────────┘
                                                                                 ▲
                                                                                 │ Telemetry & EDR
                                                                                 │ Ingestion
                                                                 ┌───────────────┴────────────────┐
                                                                 │   Local Agent (Host Machine)   │
                                                                 │   python main.py               │
                                                                 └────────────────────────────────┘
```

---

## Step 1: Deploy to Render via Blueprint (Both Frontend & Backend in 1 Click)

The project includes an enterprise `render.yaml` specification that automates provisioning of both the **FastAPI Backend** and the **React Vite Static Site** simultaneously.

1. **Sign Up / Log In:** Go to [render.com](https://render.com) and log in with your GitHub account.
2. **Deploy Blueprint:**
   - On the Render Dashboard, click **New +** → **Blueprint**.
   - Select your GitHub repository: `FixAI-Project`.
   - Render will parse `render.yaml` and discover two managed services:
     1. `fixai-backend` (Python Web Service)
     2. `fixai-frontend` (Static Site)
   - Click **Apply**.
   - Render will build both services automatically!
3. **Get Your URLs:**
   - **Backend URL:** e.g., `https://fixai-backend.onrender.com` (or `https://fixai-backend-xxxx.onrender.com`)
   - **Frontend URL:** e.g., `https://fixai-frontend.onrender.com` (or `https://fixai-frontend-xxxx.onrender.com`)
4. **Synchronize Frontend Env Variable (if custom name generated):**
   - In Render Dashboard → `fixai-frontend` → **Environment**:
   - Ensure `VITE_FASTAPI_URL` is set to your actual `fixai-backend` URL (e.g. `https://fixai-backend-xxxx.onrender.com`).
   - Trigger a deploy (`Manual Deploy` → `Clear build cache & deploy`).

---

## Step 2: Manual Render Service Setup (Alternative to Blueprint)

If you prefer to configure each service manually without Blueprint:

### 1. Backend Web Service (`fixai-backend`):
- Click **New +** → **Web Service**.
- Connect your GitHub repository.
- Configure:
  - **Name:** `fixai-backend`
  - **Root Directory:** `backend`
  - **Runtime:** `Python 3`
  - **Build Command:** `pip install --upgrade pip && pip install -r requirements.txt`
  - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
  - **Health Check Path:** `/health`
  - **Plan:** `Free`
- **Environment Variables:**
  - `PYTHON_VERSION` = `3.11.9`
  - `FIXAI_ENV` = `production`
  - `JWT_SECRET` = *(Click Generate or enter a 32+ character random key)*
  - `CONVEX_DEVICE_API_KEY` = *(Click Generate or enter a key)*
  - `DEFAULT_DEVICE_KEY` = *(Same as CONVEX_DEVICE_API_KEY)*
  - `DATABASE_URL` = `sqlite+aiosqlite:///./fixai.db` *(or your Render PostgreSQL internal URL)*
  - `CORS_ORIGINS` = `https://fixai-frontend.onrender.com,http://localhost:5173`
- Click **Create Web Service**.

### 2. Frontend Static Site (`fixai-frontend`):
- Click **New +** → **Static Site**.
- Connect your GitHub repository.
- Configure:
  - **Name:** `fixai-frontend`
  - **Root Directory:** `fixai-guardian`
  - **Build Command:** `npm install && npm run build`
  - **Publish Directory:** `dist`
- **Rewrite Rules (for Single Page App routing):**
  - Go to **Redirects/Rewrites**:
  - Add Rule: `/*` → `/index.html` (Rewrite)
- **Environment Variables:**
  - `VITE_FASTAPI_URL` = `https://fixai-backend.onrender.com` *(your actual Render backend URL)*
- Click **Create Static Site**.

---

## Step 3: Deploy Frontend to Vercel (Alternative Frontend Hosting)

If you prefer hosting the frontend on Vercel Edge while keeping the backend on Render:

1. **Sign Up / Log In:** Go to [vercel.com](https://vercel.com) and log in with your GitHub account.
2. **Import Project:**
   - Click **Add New...** → **Project**.
   - Select your GitHub repository: `FixAI-Project`.
3. **Configure Project:**
   - **Framework Preset:** `Vite`
   - **Root Directory:** Click `Edit` and select `fixai-guardian`
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
4. **Set Environment Variables:**
   - `VITE_FASTAPI_URL` = `https://fixai-backend-xxxx.onrender.com` *(your Render backend URL)*
   - `VITE_CONVEX_URL` = `https://mock.convex.cloud`
5. **Deploy:** Click **Deploy**.
   Vercel will build and assign you a global domain: `https://fixai-guardian.vercel.app`.
   *(Note: The FixAI backend automatically permits all `*.vercel.app` and `*.onrender.com` origins).*

---

## Step 4: Connect the Local Agent to your Cloud Backend

The Python Local Agent runs on your Windows machine to monitor real system logs (Event 4625), scan files for entropy/YARA, and detect WMI fileless threats:

1. Open `fixai-guardian/local_agent/.env` (or set environment variables):
   ```env
   BACKEND_URL=https://fixai-backend-xxxx.onrender.com/api/v1/agent/ingest
   FIXAI_DEVICE_API_KEY=fixai-device-secret-key-2026
   FIXAI_DEVICE_NAME=My-Windows-Workstation
   FIXAI_POLL_INTERVAL=5
   ```
2. Start the local agent:
   ```powershell
   cd fixai-guardian\local_agent
   py -3.11 main.py
   ```
3. Open your Vercel dashboard: `https://fixai-guardian.vercel.app`.
   You will see live hardware metrics, telemetry, and EDR threat statuses streaming directly to your cloud dashboard in real time!

---

## Alternative: Universal Docker Deployment

To self-host the entire system on a VPS (AWS EC2, DigitalOcean, Hetzner, etc.):

```bash
# Clone the repository
git clone https://github.com/nishita339/FixAI-Project.git
cd FixAI-Project

# Build and start both frontend and backend
docker compose up -d --build
```

- **Frontend:** `http://<your-vps-ip>:80`
- **Backend API:** `http://<your-vps-ip>:8000`
- **Health Check:** `http://<your-vps-ip>:8000/health`
