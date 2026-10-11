"""Scan history query and audit endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from phish_ai.db.database import DatabaseManager
from phish_ai.models.enums import Verdict

router = APIRouter(prefix="/scans", tags=["Scans"])


def get_db(request: Request) -> DatabaseManager:
    return request.app.state.db  # type: ignore[no-any-return]


@router.get("", response_model=list[dict[str, Any]])
async def list_scans(
    verdict: str | None = Query(
        default=None, description="Filter by verdict: CLEAN, SUSPICIOUS, PHISHING"
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: DatabaseManager = Depends(get_db),
) -> list[dict[str, Any]]:
    """List historical scan reports with optional verdict filtering."""
    verdict_enum = None
    if verdict:
        try:
            verdict_enum = Verdict(verdict.upper())
        except ValueError:
            valid_verdicts = [v.value for v in Verdict]
            raise HTTPException(
                status_code=400,
                detail=f"Invalid verdict '{verdict}'. Valid values: {valid_verdicts}",
            ) from None

    scans = db.list_scans(verdict=verdict_enum, limit=limit, offset=offset)
    return [s.model_dump(mode="json") for s in scans]


@router.get("/{scan_id}", response_model=dict[str, Any])
async def get_scan_report(
    scan_id: str,
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve full forensic scan report by scan_id."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan with id '{scan_id}' not found")
    return scan.model_dump(mode="json")
