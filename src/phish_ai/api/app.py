"""FastAPI application factory for AI Phishing Detection System."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from phish_ai.api.routes import analyze, health, scans
from phish_ai.config.settings import Settings, get_settings
from phish_ai.db.database import DatabaseManager
from phish_ai.ml.classifier import PhishingEnsembleClassifier


def create_app(
    settings: Settings | None = None,
    db: DatabaseManager | None = None,
    classifier: PhishingEnsembleClassifier | None = None,
) -> FastAPI:
    """Create and configure FastAPI application for phishing analysis."""
    resolved_settings = settings or get_settings()
    resolved_db = db or DatabaseManager(resolved_settings.db_path)
    resolved_classifier = classifier or PhishingEnsembleClassifier(resolved_settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        resolved_db.init_db()
        app.state.settings = resolved_settings
        app.state.db = resolved_db
        app.state.classifier = resolved_classifier
        yield

    app = FastAPI(
        title="AI Phishing Detection System API",
        description="REST API for email forensics, NLP body analysis, and URL risk scoring.",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Attach immediately for test fixture access before lifespan trigger
    app.state.settings = resolved_settings
    app.state.db = resolved_db
    app.state.classifier = resolved_classifier

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(analyze.router)
    app.include_router(scans.router)

    return app
