"""Optional FastAPI ingest for findings metadata (not source). Milestone 3+."""

from __future__ import annotations

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
except ImportError:  # pragma: no cover
    FastAPI = None  # type: ignore


def create_app():
    if FastAPI is None:
        raise RuntimeError("Install quantumguard[api] to run the prototype API")
    app = FastAPI(title="QuantumGuard API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.get("/health")
    def health():
        return {"status": "ok", "disclaimer": "Does not detect active quantum attacks"}

    return app
