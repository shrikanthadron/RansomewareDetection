# RansomShield AI — Ransomware Detection Using Supervised Machine Learning Algorithms

RansomShield AI is a full-stack defensive cybersecurity platform combining **static Portable Executable (PE) analysis**, **supervised machine learning classification** (Random Forest, Decision Tree, SVM, XGBoost), **0–100 risk scoring**, **opt-in process monitoring**, **safe quarantine**, and **ReportLab PDF reporting**, backed by **PostgreSQL**, **FastAPI**, and **React + TypeScript**.

> **Safety Notice:** Uploaded binaries are **never executed**. All PE inspection is strictly static via `pefile` and `hashlib`. Process monitoring uses read-only `psutil` metadata and never terminates or quarantines OS-critical processes.

---

## Architecture

- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Recharts, TanStack Query, Axios, React Router, Lucide Icons
- **Backend:** Python 3.11+, FastAPI, SQLAlchemy 2.0, Alembic, PyJWT, `pwdlib` (Argon2/bcrypt), WebSockets
- **Database:** PostgreSQL 16/18 (UUID primary keys, JSONB, foreign keys, indexes, Alembic migrations)
- **ML Pipeline:** Scikit-learn, XGBoost, Pandas, NumPy, Joblib, Matplotlib, Seaborn
- **Static PE & Telemetry:** `pefile`, `psutil`, `hashlib`, `pathlib`, `reportlab`

---

## Initial Development Administrator Setup

Credentials are **never hardcoded** in source code. Configure initial bootstrap credentials via environment variables (or `.env`) before starting the backend:

```env
INITIAL_ADMIN_EMAIL=admin@ransomshield.dev
INITIAL_ADMIN_PASSWORD=ChangeMeAdmin!2026
INITIAL_ADMIN_NAME=Security Administrator
```

On first startup, `bootstrap_database()` checks if `INITIAL_ADMIN_EMAIL` exists in PostgreSQL and creates the `ADMIN` account using Argon2 password hashing. Change `JWT_SECRET_KEY` and `INITIAL_ADMIN_PASSWORD` before deploying to any shared or production environment.

---

## Running with Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

- Frontend UI: `http://localhost:3000`
- Backend API & Swagger Docs: `http://localhost:8000/docs`
- PostgreSQL: `localhost:5432`

---

## Running Locally on Windows (PostgreSQL + Python + Vite)

### 1. Start PostgreSQL and create database
Ensure PostgreSQL is running and create the database/user matching `.env`:
```sql
CREATE USER ransomshield WITH PASSWORD 'ransomshield_dev_pass';
CREATE DATABASE ransomshield OWNER ransomshield;
```

### 2. Backend Setup
```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy ..\.env.example ..\.env
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

### 3. Frontend Setup
```powershell
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173`.

---

## Dataset CSV Format & Label Mapping

Datasets uploaded via **Dataset Manager** (Admin-only) support:
- Standard static PE schema (`v1.0.0`, 32 numeric features matching `backend/app/services/pe_extractor.py`) **or** custom numeric feature CSVs.
- Automatic or configurable label column (`label`, `class`, `target`, `malware`, `is_ransomware`, `legitimate`).
- Supported label values: `0 / benign / legitimate / clean` (Class 0) and `1 / ransomware / malware / malicious` (Class 1), or custom JSON mapping.
- All imputers, scalers (`StandardScaler`/`MinMaxScaler`), and feature selectors (`Mutual Information` / `Chi-Square`) are fit **strictly on the training split** (`80/20` stratified default) to prevent data leakage.

A safe synthetic dataset generator is included in `sample_data/generate_sample_dataset.py` to produce `sample_data/ransomshield_sample_dataset.csv` for testing ML training and inference end-to-end.

---

## Running Automated Tests

```powershell
cd backend
.venv\Scripts\pytest -v
```
