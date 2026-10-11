"""Service health and operational status endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, Request

from phish_ai.db.database import DatabaseManager

router = APIRouter(prefix="/health", tags=["Health"])


def get_db(request: Request) -> DatabaseManager:
    """Dependency retrieving database manager from app state."""
    db: DatabaseManager = request.app.state.db
    return db


@router.get("", response_model=dict[str, Any])
async def health_check(db: DatabaseManager = Depends(get_db)) -> dict[str, Any]:
    """Return health check and persistent database connectivity status."""
    total_scans = len(db.list_scans(limit=1))
    return {
        "status": "healthy",
        "service": "ai-phishing-detection-system",
        "database_connected": True,
        "sample_query_success": total_scans >= 0,
    }
