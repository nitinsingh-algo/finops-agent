from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from langgraph.checkpoint.memory import InMemorySaver

from algo_finops.agents.iac.adapters.github import event_to_state, parse_event, verify_signature
from algo_finops.agents.iac.domain import WebhookVerificationError
from algo_finops.agents.iac.graph import build_iac_graph
from algo_finops.agents.iac.runtime import IACRuntime, build_runtime
from algo_finops.config import get_settings
from algo_finops.persistence.session import init_db

logger = logging.getLogger(__name__)


def create_app(*, runtime: IACRuntime | None = None, graph=None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if runtime is not None:
            app.state.runtime = runtime
            app.state.graph = graph or build_iac_graph(runtime, checkpointer=InMemorySaver())
            app.state.engine = None
            yield
            return

        settings = get_settings()
        logging.basicConfig(level=settings.log_level)
        factory, engine = await init_db(settings.database_url)
        bound = build_runtime(settings, factory)
        app.state.runtime = bound
        app.state.graph = build_iac_graph(bound, checkpointer=InMemorySaver())
        app.state.engine = engine
        yield
        await engine.dispose()

    app = FastAPI(title="Algo-Finops IAC Agent", lifespan=lifespan)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "agent": "iac"}

    @app.get("/runs/{run_id}")
    async def get_run(run_id: str, request: Request) -> JSONResponse:
        row = await request.app.state.runtime.runs.get(run_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Run not found")
        return JSONResponse(row)

    @app.post("/webhooks/github")
    async def github_webhook(request: Request, background: BackgroundTasks) -> JSONResponse:
        settings = request.app.state.runtime.settings
        payload = await request.body()
        try:
            verify_signature(
                secret=settings.github_webhook_secret,
                payload=payload,
                signature_header=request.headers.get("x-hub-signature-256"),
            )
        except WebhookVerificationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

        delivery_id = request.headers.get("x-github-delivery") or str(uuid4())
        event_name = request.headers.get("x-github-event") or ""
        try:
            event = parse_event(delivery_id=delivery_id, event_name=event_name, payload=payload)
        except WebhookVerificationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        existing = await request.app.state.runtime.runs.get_by_delivery(delivery_id)
        if existing and existing["status"] in {"analyzed", "skipped"}:
            return JSONResponse({"run_id": existing["id"], "status": existing["status"], "idempotent": True})

        run_id = existing["id"] if existing else str(uuid4())
        initial = {
            "run_id": run_id,
            "status": "received",
            "findings": [],
            "errors": [],
            **event_to_state(event),
        }
        background.add_task(_invoke_graph, request.app.state.graph, request.app.state.runtime, initial, run_id)
        return JSONResponse({"run_id": run_id, "delivery_id": delivery_id, "status": "accepted"}, status_code=202)

    return app


async def _invoke_graph(graph, runtime: IACRuntime, initial: dict, thread_id: str) -> None:
    try:
        await graph.ainvoke(initial, {"configurable": {"thread_id": thread_id}})
    except Exception:
        logger.exception("IAC graph failed for run %s", initial.get("run_id"))
        await runtime.runs.mark(initial["run_id"], status="failed", error="internal graph error")


app = create_app()
