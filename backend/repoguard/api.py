"""Application factory keeps initialization explicit and testable."""

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.requests import Request

from repoguard.config import Settings
from repoguard.database import make_engine, sessions
from repoguard.github import GitHub
from repoguard.input_limits import InputLimits
from repoguard.observability import CorrelationMiddleware, configure_logging
from repoguard.observability import router as operations_router
from repoguard.proposal_routes import router as proposal_router
from repoguard.routes import router
from repoguard.validation import ValidatorClient
from repoguard.webhooks import router as webhook_router


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings()
    configure_logging()
    app = FastAPI(title="RepoGuard", version="0.1.0")
    app.state.settings = config
    app.state.engine = make_engine(config.database_url)
    app.state.sessions = sessions(app.state.engine)
    app.state.github = GitHub(config)
    app.state.validator = ValidatorClient(config)
    app.include_router(router)
    app.include_router(webhook_router)
    app.include_router(proposal_router)
    app.include_router(operations_router)
    app.add_middleware(CorrelationMiddleware)
    app.add_middleware(InputLimits)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_: Request, __: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": "invalid request"}, status_code=422)

    @app.get("/health/live")
    def live() -> dict[str, str]:
        return {"status": "ok", "service": "repoguard", "mode": config.environment}

    return app
