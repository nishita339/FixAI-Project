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

## Step 1: Deploy Backend to Render (or Railway)

### Option A: Render (Recommended — Blueprint Ready)

1. **Sign Up / Log In:** Go to [render.com](https://render.com) and sign in with your GitHub account.
2. **Create New Blueprint:**
   - Click **New +** → **Blueprint**.
   - Connect your GitHub repository: `nishita339/FixAI-Project`.
   - Render automatically detects `render.yaml` and provisions the `fixai-backend` service.
   - Click **Apply**.
3. **Manual Web Service (Alternative if not using Blueprint):**
   - Click **New +** → **Web Service**.
   - Select your repository: `nishita339/FixAI-Project`.
   - Configure settings:
     - **Name:** `fixai-backend`
     - **Root Directory:** `backend`
     - **Runtime:** `Python 3`
     - **Build Command:** `pip install --upgrade pip && pip install -r requirements.txt`
     - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
     - **Plan:** `Free`
   - **Environment Variables:**
     - `PYTHON_VERSION` = `3.11.9`
     - `FIXAI_ENV` = `production`
     - `JWT_SECRET` = *(Click Generate or enter a secure 32+ char key)*
     - `CONVEX_DEVICE_API_KEY` = `fixai-device-secret-key-2026`
     - `DEFAULT_DEVICE_KEY` = `fixai-device-secret-key-2026`
     - `CORS_ORIGINS` = `https://<your-vercel-app>.vercel.app,http://localhost:5173`
   - Click **Create Web Service**.
4. **Copy your Backend URL:** Once deployed, Render will provide a public URL like:
   `https://fixai-backend-xxxx.onrender.com`
   Test it by opening: `https://fixai-backend-xxxx.onrender.com/health` (should return `{"status": "healthy"}`).

---

## Step 2: Deploy Frontend to Vercel

1. **Sign Up / Log In:** Go to [vercel.com](https://vercel.com) and log in with your GitHub account.
2. **Import Project:**
   - Click **Add New...** → **Project**.
   - Select `nishita339/FixAI-Project` from your repository list.
3. **Configure Project:**
   - **Framework Preset:** `Vite`
   - **Root Directory:** Click `Edit` and select `fixai-guardian`
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
4. **Set Environment Variables:**
   Add the following under **Environment Variables**:
   - `VITE_FASTAPI_URL` = `https://fixai-backend-xxxx.onrender.com` *(your Render backend URL from Step 1)*
   - `VITE_CONVEX_URL` = `https://mock.convex.cloud`
5. **Deploy:** Click **Deploy**.
   Vercel will build and assign you a global domain:
   `https://fixai-guardian.vercel.app`

---

## Step 3: Link Backend CORS to your Vercel Domain

1. Go back to your **Render Dashboard** → `fixai-backend` → **Environment**.
2. Update the `CORS_ORIGINS` variable:
   ```env
   CORS_ORIGINS=https://fixai-guardian.vercel.app
   ```
3. Save changes. Render will automatically re-deploy with your custom frontend domain allowed.

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
