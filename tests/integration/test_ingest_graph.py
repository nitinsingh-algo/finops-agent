from __future__ import annotations

from algo_finops.agents.iac.adapters.github import event_to_state
from algo_finops.agents.iac.domain import TokenResolutionError
from algo_finops.agents.iac.graph import build_iac_graph
from algo_finops.agents.iac.runtime import IACRuntime
from tests.helpers import make_event


async def test_ingest_stage_emits_blueprint(runtime: IACRuntime) -> None:
    graph = build_iac_graph(runtime)
    event = make_event()
    result = await graph.ainvoke(
        {
            "run_id": "run-1",
            "status": "received",
            "findings": [],
            "errors": [],
            **event_to_state(event),
        }
    )
    assert result["status"] == "analyzed"
    blueprint = result["blueprint"]
    kinds = {item["kind"] for item in blueprint["iac_systems"]}
    assert "terraform" in kinds
    assert "docker" in kinds
    assert result["clone_path"]
    assert result["sandbox"]["provider"] == "local"


async def test_ping_short_circuits(runtime: IACRuntime) -> None:
    graph = build_iac_graph(runtime)
    event = make_event(event_name="ping", clone_url="", repo_full_name="ping")
    result = await graph.ainvoke(
        {
            "run_id": "run-ping",
            "status": "received",
            "findings": [],
            "errors": [],
            **event_to_state(event),
        }
    )
    assert result["status"] == "skipped"
    assert result.get("blueprint") is None
    assert runtime.tokens.calls == 0  # type: ignore[attr-defined]


async def test_token_failure_stops_before_clone(runtime: IACRuntime) -> None:
    class BoomTokens:
        async def resolve(self, event):
            raise TokenResolutionError("no credential")

    runtime.tokens = BoomTokens()
    graph = build_iac_graph(runtime)
    event = make_event()
    result = await graph.ainvoke(
        {
            "run_id": "run-fail",
            "status": "received",
            "findings": [],
            "errors": [],
            **event_to_state(event),
        }
    )
    assert result["status"] == "failed"
    assert result["errors"]
    assert result.get("clone_path") is None
