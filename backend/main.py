
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from scanner import run_scan
from database import init_db, save_scan, get_scans, get_scan_by_id


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="AIShield Security Scanner API",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:8002",
        "http://127.0.0.1:8002",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/")
def home():
    return {
        "message": "AIShield Security Scanner API is running"
    }


@app.post("/scan")
def scan():
    result = run_scan()

    scan_id, timestamp = save_scan(result)

    return {
        **result,
        "scan_id": scan_id,
        "timestamp": timestamp,
    }


@app.get("/scans")
def list_scans():
    return get_scans()


@app.get("/scans/{scan_id}")
def scan_details(scan_id: int):
    result = get_scan_by_id(scan_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    return result
