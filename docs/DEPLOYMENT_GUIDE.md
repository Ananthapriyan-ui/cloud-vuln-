# CloudVuln — Production Deployment Guide

This guide provides step-by-step instructions for deploying the **CloudVuln** security engine to production using **Vercel** for the frontend and **Render** for the backend API server, with **Supabase PostgreSQL** as the primary database.

---

## 📋 Prerequisites & Tools

- GitHub Account (with project repository pushed)
- [Vercel Account](https://vercel.com)
- [Render Account](https://render.com)
- [Supabase Account](https://supabase.com) — free tier is sufficient
- Python 3.10+ & Node.js 18+ locally

---

## 🗄️ Part 0: Supabase PostgreSQL Setup (Do This First)

### Step 1: Create a Supabase Project

1. Log into [Supabase Dashboard](https://supabase.com/dashboard).
2. Click **New Project**.
3. Choose an organization, enter a project name (e.g. `cloudvuln`), set a strong database password, and select the nearest region.
4. Wait for the project to spin up (~1 minute).

### Step 2: Get Your Database Connection String

1. In your Supabase project, navigate to **Settings → Database**.
2. Under **Connection string**, choose **Transaction pooler** (port `6543`) for production deployments, or **Session pooler** (port `5432`) for local development.
3. Copy the URI — it looks like:
   ```
   postgresql://postgres.[ref]:[your-password]@aws-0-ap-south-1.pooler.supabase.com:6543/postgres
   ```

### Step 3: Apply Schema (First Time Only)

Run the schema migration from your local machine:

```bash
cd backend
# Set DATABASE_URL in backend/.env pointing to your Supabase project
python migrate_db.py
```

This creates all tables (`users`, `scans`, `vulnerabilities`, `activity_logs`, `reports`) directly in Supabase PostgreSQL.

### Step 4: Get API Keys for Supabase Storage (Optional)

If you want reports stored in Supabase Storage:
1. Navigate to **Settings → API**.
2. Copy the **Project URL** (`SUPABASE_URL`) and **Service Role Key** (`SUPABASE_SERVICE_ROLE_KEY`).
3. Create a private bucket named `reports` in **Storage**.

---

## 🛠️ Part 1: Backend Deployment on Render

### Step 1: Create Web Service on Render

1. Log into your **Render Dashboard** (`https://dashboard.render.com`).
2. Click **New +** → **Web Service**.
3. Connect your GitHub repository containing `cloudvuln`.
4. Configure service parameters:
   - **Name**: `cloudvuln-api`
   - **Region**: Oregon (US West) or nearest region
   - **Branch**: `main`
   - **Root Directory**: (Leave blank)
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r backend/requirements.txt`
   - **Start Command**: `cd backend && gunicorn -c gunicorn.conf.py main:app`

> **No persistent disk is needed.** CloudVuln now uses Supabase PostgreSQL as the primary database, which is hosted externally. Render is stateless.

### Step 2: Configure Backend Environment Variables

In the Render Web Service **Environment** tab, set the following environment variables:

| Key | Value | Description |
| :--- | :--- | :--- |
| `APP_ENV` | `production` | Enables production error handling |
| `LOG_LEVEL` | `INFO` | Controls logging verbosity |
| `PORT` | `8000` | Internal application port |
| `BIND` | `0.0.0.0:8000` | Binding network interface |
| `SECRET_KEY` | `[Generate 64-char hex]` | Primary JWT signature key |
| `REFRESH_SECRET_KEY` | `[Generate 64-char hex]` | JWT Refresh token key |
| `ALLOWED_ORIGINS` | `https://cloudvuln-frontend.vercel.app` | Allowed CORS origins |
| `DATABASE_URL` | `postgresql://postgres.[ref]:[pw]@[host]:6543/postgres` | **Supabase PostgreSQL connection string** |
| `SUPABASE_URL` | `https://[ref].supabase.co` | Supabase project URL (for Storage) |
| `SUPABASE_SERVICE_ROLE_KEY` | `[your-service-role-key]` | Supabase service role key (keep secret!) |
| `SUPABASE_STORAGE_BUCKET` | `reports` | Storage bucket name for report files |

> ⚠️ **NEVER** commit `DATABASE_URL` or `SUPABASE_SERVICE_ROLE_KEY` to your repository. Set them only in the Render Dashboard environment.

Click **Save Changes**. Render will trigger automatic deployment.

---

## 🚀 Part 2: Frontend Deployment on Vercel

### Step 1: Import Project into Vercel

1. Log into **Vercel Dashboard** (`https://vercel.com/dashboard`).
2. Click **Add New...** → **Project**.
3. Import your `cloudvuln` repository.

### Step 2: Configure Build Settings & Environment Variables

1. **Framework Preset**: `Vite`
2. **Root Directory**: `./`
3. **Build Command**: `npm run build`
4. **Output Directory**: `dist`
5. **Environment Variables**:
   - `VITE_SUPABASE_URL` → `https://[ref].supabase.co`
   - `VITE_SUPABASE_ANON_KEY` → `[your-anon-key]`
   - `VITE_API_URL` → `https://cloudvuln-api.onrender.com/api` (your Render API URL)

6. Click **Deploy**.

---

## 🔐 Part 3: Google OAuth & Supabase Configuration

To enable one-click Google Sign-In and Registration in CloudVuln:

### Step 1: Create OAuth Credentials in Google Cloud Console
1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. Navigate to **APIs & Services** > **Credentials**.
3. Click **Create Credentials** > **OAuth client ID**.
4. Select **Web application** as the application type.
5. In **Authorized redirect URIs**, add your Supabase Auth callback URI:
   ```
   https://<your-supabase-project-ref>.supabase.co/auth/v1/callback
   ```
6. Click **Create** and copy your **Client ID** and **Client Secret**.

### Step 2: Configure Google Provider in Supabase
1. Open your [Supabase Dashboard](https://supabase.com/dashboard).
2. Go to **Authentication** > **Providers** > **Google**.
3. Toggle **Enable Google provider** to ON.
4. Paste the **Client ID** and **Client Secret** obtained from Google Cloud Console.
5. Click **Save**.

### Step 3: Configure Redirect & Site URLs
1. In Supabase Dashboard, navigate to **Authentication** > **URL Configuration**.
2. Set **Site URL** to your deployed frontend domain (e.g., `https://cloudvuln.vercel.app` or `http://localhost:5173`).
3. Add any preview/staging URLs to **Redirect URLs** (e.g., `http://localhost:5173/*`, `https://*.vercel.app/*`).
4. Click **Save**.

---

## 🔄 Part 4: Database Backup

Supabase automatically handles backups at the infrastructure level:
- **Free Plan**: Daily backups retained for 7 days (via Supabase Dashboard → Database → Backups).
- **Pro Plan**: Point-in-Time Recovery (PITR) with up to 30-day retention.

To additionally export a local JSON snapshot of your data:

```bash
cd backend
# Requires DATABASE_URL set in backend/.env
python backup_db.py
```

Backup files will be stored in `backend/backups/cloudvuln_backup_YYYYMMDD_HHMMSS.json`.

---

## ✅ Deployment Verification Checklist

- [ ] Frontend successfully deployed on Vercel without build errors.
- [ ] Backend API responding to health check: `GET https://cloudvuln-api.onrender.com/api/health`.
- [ ] Health check returns `"database": "Supabase PostgreSQL"` and `"database_connected": true`.
- [ ] Supabase Authentication configured with Google OAuth provider enabled.
- [ ] Login and Registration functional via both Google OAuth and Email/Password.
- [ ] New scan trigger saves records to Supabase PostgreSQL (verify via Supabase Table Editor).
- [ ] HTML and CSV executive report downloads function correctly.
