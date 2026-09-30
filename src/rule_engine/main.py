from fastapi import FastAPI

from .api import routes_audit, routes_catalog, routes_health, routes_validate
from .version import ENGINE_VERSION


def create_app() -> FastAPI:
    app = FastAPI(title="ClaimGuard Rule Engine", version=ENGINE_VERSION,
                  description="Stateless deterministic validation of healthcare claim "
                              "envelopes against the fictional payer rulebook (R001-R015).")
    for r in (routes_health.router, routes_validate.router, routes_catalog.router, routes_audit.router):
        app.include_router(r)
    return app


app = create_app()
