"""AQL-1 backend entrypoint.

Run with:
    uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.billing import router as billing_router
from api.routes import router
from core.auth import APIKeyMiddleware
from core.config import get_settings

settings = get_settings()


def create_app(auth_enabled: bool | None = None) -> FastAPI:
    """Build the FastAPI application.

    ``auth_enabled`` overrides the ``AUTH_ENABLED`` setting for this instance,
    which lets tests exercise the authenticated surface without touching the
    process environment. ``None`` (the default) defers to the setting.
    """
    app = FastAPI(
        title=f"{settings.app_name} API",
        version="0.1.0",
        description="Autonomous AI agent operating layer — backend API.",
    )

    # Middleware order matters: Starlette builds the stack so the LAST added
    # middleware is the OUTERMOST. Auth is added first so CORS wraps it — that
    # way preflight requests are answered before auth, and 401/429 responses
    # still carry the CORS headers a browser needs to read them.
    app.add_middleware(APIKeyMiddleware, enabled=auth_enabled)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        # Let the browser read the rate-limit headers off a cross-origin call.
        expose_headers=[
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Retry-After",
        ],
    )

    app.include_router(router)
    # Billing lives in its own module (``api/billing.py``) and mounts under
    # ``/v1/billing`` (manual Payoneer / bank-transfer verification).
    app.include_router(billing_router)

    @app.get("/", tags=["meta"])
    def root() -> dict:
        return {
            "service": settings.app_name,
            "version": "0.1.0",
            "docs": "/docs",
            "health": "/health",
            "auth": "api-key" if settings.auth_enabled else "disabled",
            "billing": "payoneer-manual" if settings.payoneer_configured else "demo",
        }

    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
    )
