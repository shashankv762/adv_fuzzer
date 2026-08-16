"""
ACFP Dashboard API - FastAPI REST API for fuzzing platform
"""
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import sqlite3
import json
import os
from datetime import datetime

app = FastAPI(title="ACFP Dashboard API", version="1.0.0")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Key authentication
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
API_KEYS = {"admin-key-12345": "admin", "researcher-key-67890": "researcher"}

DB_PATH = os.environ.get("ACFP_DB_PATH", "/workspace/acfp.db")

class Crash(BaseModel):
    id: str
    crash_hash: str
    type: str
    severity: str
    target_name: str
    cwe_candidate: str
    cvss_score: float
    first_seen: int
    state: int

class Job(BaseModel):
    id: str
    name: str
    target: str
    backend: str
    status: str

class Stats(BaseModel):
    total_execs: int
    unique_crashes: int
    corpus_size: int
    execs_per_sec: float

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

async def get_api_key(api_key: str = Security(API_KEY_HEADER)):
    if not api_key or api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return API_KEYS[api_key]

@app.get("/")
async def root():
    return {"message": "ACFP Dashboard API", "version": "1.0.0"}

@app.get("/api/stats")
async def get_stats():
    """Get current fuzzer statistics"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Count crashes
        cursor.execute("SELECT COUNT(*) FROM crashes")
        crash_count = cursor.fetchone()[0]
        
        # Count jobs
        cursor.execute("SELECT COUNT(*) FROM jobs WHERE state = 1")
        active_jobs = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_execs": 0,
            "unique_crashes": crash_count,
            "corpus_size": 0,
            "execs_per_sec": 0.0,
            "active_jobs": active_jobs
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/crashes", response_model=List[Crash])
async def list_crashes(
    limit: int = 100, 
    offset: int = 0,
    user: str = Depends(get_api_key)
):
    """List all crashes with pagination"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM crashes ORDER BY first_seen DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        rows = cursor.fetchall()
        conn.close()
        
        crashes = []
        for row in rows:
            crashes.append(Crash(
                id=row["id"],
                crash_hash=row["crash_hash"],
                type=row["type"],
                severity=row["severity"],
                target_name=row["target_name"],
                cwe_candidate=row.get("cwe_candidate", ""),
                cvss_score=row.get("cvss_score", 0.0),
                first_seen=row["first_seen"],
                state=row.get("state", 0)
            ))
        return crashes
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/crashes/{crash_id}")
async def get_crash(crash_id: str, user: str = Depends(get_api_key)):
    """Get detailed crash information"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM crashes WHERE id = ?", (crash_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=404, detail="Crash not found")
        
        return dict(row)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/crashes/{crash_id}/lifecycle")
async def update_lifecycle(
    crash_id: str,
    state: int,
    user: str = Depends(get_api_key)
):
    """Update crash lifecycle state"""
    if user not in ["admin", "researcher"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE crashes SET state = ? WHERE id = ?",
            (state, crash_id)
        )
        conn.commit()
        conn.close()
        return {"status": "updated", "crash_id": crash_id, "state": state}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/jobs", response_model=List[Job])
async def list_jobs(user: str = Depends(get_api_key)):
    """List all fuzzing jobs"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM jobs ORDER BY created DESC")
        rows = cursor.fetchall()
        conn.close()
        
        jobs = []
        for row in rows:
            jobs.append(Job(
                id=row["id"],
                name=row["name"],
                target=row.get("target", ""),
                backend=row.get("backend", "native"),
                status="running" if row.get("state") == 1 else "stopped"
            ))
        return jobs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/jobs")
async def create_job(job: Job, user: str = Depends(get_api_key)):
    """Create a new fuzzing job"""
    if user not in ["admin", "researcher"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO jobs (id, name, target, backend, state, created) VALUES (?, ?, ?, ?, 1, ?)",
            (job.id, job.name, job.target, job.backend, int(datetime.now().timestamp()))
        )
        conn.commit()
        conn.close()
        return {"status": "created", "job_id": job.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/{crash_id}/markdown")
async def generate_markdown_report(crash_id: str, user: str = Depends(get_api_key)):
    """Generate CVE-ready markdown report"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM crashes WHERE id = ?", (crash_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=404, detail="Crash not found")
        
        report = f"""# Vulnerability Report: {row['id']}

## Summary
- **Crash ID**: {row['id']}
- **Type**: {row['type']}
- **Severity**: {row['severity']}
- **CWE**: {row.get('cwe_candidate', 'TBD')}
- **CVSS Score**: {row.get('cvss_score', 'TBD')}

## Technical Details
- **Target**: {row['target_name']}
- **First Seen**: {datetime.fromtimestamp(row['first_seen']).isoformat()}
- **Crash Hash**: {row['crash_hash']}

## Exploitability Assessment
This crash has been automatically classified as {row['severity']} severity.
Manual analysis is required for authoritative assessment.

## Reproduction Steps
1. Build target with sanitizers enabled
2. Run target with provided crash input
3. Observe crash with sanitizer output

## Remediation Recommendations
Review code at crash location and add appropriate input validation.
Enable ASan/UBSan during development testing.

---
*Generated by ACFP Platform v1.0.0 - For authorized security research only*
"""
        return {"content": report, "format": "markdown"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.on_event("startup")
async def init_db():
    """Initialize database tables"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS crashes (
            id TEXT PRIMARY KEY,
            crash_hash TEXT,
            type TEXT,
            severity TEXT,
            exploitability TEXT,
            target_name TEXT,
            harness_name TEXT,
            cwe_candidate TEXT,
            cvss_score REAL,
            first_seen INTEGER,
            last_seen INTEGER,
            state INTEGER DEFAULT 0,
            notes TEXT
        )""")
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            name TEXT,
            target TEXT,
            backend TEXT,
            state INTEGER DEFAULT 0,
            created INTEGER,
            started INTEGER,
            finished INTEGER
        )""")
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            role TEXT,
            api_key_hash TEXT,
            created INTEGER
        )""")
        
        conn.commit()
        conn.close()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
