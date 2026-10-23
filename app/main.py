import logging
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app import database
from app.scanner import scan_url
from app.security import URLValidationError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

FindingStatus = Literal["pass", "warning", "error"]
FindingSeverity = Literal["informational", "low", "medium", "high"]
ScanStatus = Literal["completed", "completed_with_warnings", "error"]


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class Finding(BaseModel):
    check_name: str
    status: FindingStatus
    severity: FindingSeverity
    explanation: str
    remediation: str


class ScanSummary(BaseModel):
    id: str
    url: str
    scanned_at: datetime
    http_status: int | None
    status: ScanStatus


class ScanResponse(ScanSummary):
    findings: list[Finding]


class ScanListResponse(BaseModel):
    scans: list[ScanSummary]


class HealthResponse(BaseModel):
    status: Literal["ok"]


def create_app(
    database_path: Path = database.DATABASE_PATH,
    transport: httpx.BaseTransport | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        database.initialize_database(database_path)
        yield

    application = FastAPI(
        title="Mini Web Security Scanner",
        description="A small, non-invasive scanner for common HTTPS and response-header configuration.",
        version="1.0.0",
        lifespan=lifespan,
    )

    @application.get("/", include_in_schema=False)
    def home() -> FileResponse:
        return FileResponse(Path(__file__).parent / "static" / "index.html")

    @application.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @application.post("/scans", response_model=ScanResponse, status_code=201)
    def create_scan(request: ScanRequest) -> ScanResponse:
        try:
            result = scan_url(request.url, transport=transport)
        except URLValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            logger.exception("Unexpected scan failure (%s).", type(exc).__name__)
            raise HTTPException(
                status_code=500,
                detail="The scan could not be completed because of an internal error.",
            ) from exc

        scan = {
            "id": str(uuid4()),
            "url": request.url,
            "scanned_at": datetime.now(timezone.utc),
            "http_status": result["http_status"],
            "status": result["status"],
            "findings": result["findings"],
        }
        scan["scanned_at"] = scan["scanned_at"].isoformat()
        try:
            database.save_scan(database_path, scan)
        except sqlite3.Error as exc:
            logger.error("Could not save scan result (%s).", type(exc).__name__)
            raise HTTPException(
                status_code=500,
                detail="The scan completed, but its result could not be saved.",
            ) from exc
        return ScanResponse(**scan)

    @application.get("/scans", response_model=ScanListResponse)
    def scan_history(
        limit: int = Query(default=20, ge=1, le=100),
    ) -> ScanListResponse:
        try:
            scans = database.list_scans(database_path, limit)
        except sqlite3.Error as exc:
            logger.error("Could not read scan history (%s).", type(exc).__name__)
            raise HTTPException(status_code=500, detail="Scan history is unavailable.") from exc
        return ScanListResponse(scans=scans)

    @application.get("/scans/{scan_id}", response_model=ScanResponse)
    def scan_details(scan_id: str) -> ScanResponse:
        try:
            scan = database.get_scan(database_path, scan_id)
        except sqlite3.Error as exc:
            logger.error("Could not read scan result (%s).", type(exc).__name__)
            raise HTTPException(status_code=500, detail="The scan result is unavailable.") from exc
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan ID was not found.")
        return ScanResponse(**scan)

    return application


app = create_app()
