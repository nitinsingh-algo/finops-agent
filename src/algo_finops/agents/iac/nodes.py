from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from algo_finops.agents.iac.adapters.github import state_to_event
from algo_finops.agents.iac.domain import (
    AnalyzerFinding,
    CloneResult,
    IACError,
    ProjectBlueprint,
    SandboxHandle,
)
from algo_finops.agents.iac.runtime import IACRuntime
from algo_finops.agents.iac.state import IACState

logger = logging.getLogger(__name__)

_FAILED = "failed"
_ANALYZED = "analyzed"
_SKIPPED = "skipped"


class IACNodes:
    def __init__(self, runtime: IACRuntime) -> None:
        self._rt = runtime

    async def ingest_webhook(self, state: IACState) -> dict[str, Any]:
        event = state_to_event(state)
        await self._rt.runs.create(state["run_id"], event)
        if event.event_name == "ping":
            await self._rt.runs.mark(state["run_id"], status=_SKIPPED)
            return {"status": _SKIPPED}
        if not event.clone_url or not event.repo_full_name:
            return _fail(state, "Webhook is missing repository identity")
        await self._rt.runs.mark(state["run_id"], status="ingested")
        return {"status": "ingested"}

    async def resolve_token(self, state: IACState) -> dict[str, Any]:
        event = state_to_event(state)
        try:
            token = await self._rt.tokens.resolve(event)
        except IACError as exc:
            return await self._fail_run(state, str(exc))
        if not token:
            return await self._fail_run(state, "Token resolver returned an empty credential")
        return {"token_ready": True, "status": "authenticated"}

    async def clone_repository(self, state: IACState) -> dict[str, Any]:
        event = state_to_event(state)
        try:
            token = await self._rt.tokens.resolve(event)
            result = await self._rt.cloner.clone(event, token, state["run_id"])
        except IACError as exc:
            return await self._fail_run(state, str(exc))
        await self._rt.runs.mark(state["run_id"], status="cloned")
        return {
            "clone_path": result.path,
            "commit_sha": result.commit_sha,
            "status": "cloned",
        }

    async def prepare_sandbox(self, state: IACState) -> dict[str, Any]:
        clone_path = state.get("clone_path")
        if not clone_path:
            return await self._fail_run(state, "Clone path missing before sandbox setup")
        clone = CloneResult(
            run_id=state["run_id"],
            path=clone_path,
            commit_sha=state.get("commit_sha") or "unknown",
            branch=state.get("ref") or state.get("default_branch") or "main",
        )
        try:
            handle = await self._rt.sandbox.create(clone)
        except IACError as exc:
            return await self._fail_run(state, str(exc))
        await self._rt.runs.mark(state["run_id"], status="sandboxed")
        return {"sandbox": handle.model_dump(), "status": "sandboxed"}

    async def analyze_project_structure(self, state: IACState) -> dict[str, Any]:
        if state.get("status") == _FAILED:
            return {}
        findings = [AnalyzerFinding.model_validate(item) for item in state.get("findings") or []]
        pending = list(state.get("pending_analyzers") or [])
        if findings and not pending:
            blueprint = _assemble_blueprint(state, findings)
            await self._rt.runs.mark(state["run_id"], status=_ANALYZED, blueprint=blueprint)
            return {"blueprint": blueprint.model_dump(), "status": _ANALYZED}
        return {"status": "analyzing"}

    async def run_analysis_engine(self, state: IACState) -> dict[str, Any]:
        workdir = _workdir(state)
        if workdir is None:
            return await self._fail_run(state, "No sandbox or clone path available for analysis")
        only = state.get("pending_analyzers") or None
        try:
            findings = self._rt.analysis.analyze(workdir, only=only)
        except IACError as exc:
            return await self._fail_run(state, str(exc))
        follow_up = sorted(
            {
                name
                for finding in findings
                for name in finding.follow_up
                if name not in {item.analyzer for item in findings}
            }
        )
        return {
            "findings": [finding.model_dump() for finding in findings],
            "pending_analyzers": follow_up,
            "status": "engine_complete",
        }

    async def _fail_run(self, state: IACState, message: str) -> dict[str, Any]:
        logger.warning("IAC run %s failed: %s", state.get("run_id"), message)
        await self._rt.runs.mark(state["run_id"], status=_FAILED, error=message)
        return _fail(state, message)


def route_after_ingest(state: IACState) -> str:
    if state.get("event_name") == "ping" or state.get("status") in {_SKIPPED, _FAILED}:
        return "__end__"
    return "resolve_token"


def route_if_healthy(next_node: str):
    def _route(state: IACState) -> str:
        if state.get("status") == _FAILED:
            return "__end__"
        return next_node

    return _route


def route_after_analyze(on_complete: str):
    def _route(state: IACState) -> str:
        if state.get("status") == _FAILED:
            return "__end__"
        if state.get("status") == _ANALYZED:
            return on_complete
        return "run_analysis_engine"

    return _route


def _assemble_blueprint(state: IACState, findings: list[AnalyzerFinding]) -> ProjectBlueprint:
    runtime = next((item for item in findings if item.kind == "runtime"), None)
    iac_systems = [item for item in findings if item.kind != "runtime"]
    sandbox = SandboxHandle.model_validate(state["sandbox"]) if state.get("sandbox") else None
    kinds = ", ".join(item.kind for item in iac_systems) or "no IaC"
    return ProjectBlueprint(
        run_id=state["run_id"],
        repo_full_name=state.get("repo_full_name") or "",
        commit_sha=state.get("commit_sha") or "unknown",
        languages=list((runtime.metadata.get("languages") if runtime else []) or []),
        package_managers=list((runtime.metadata.get("package_managers") if runtime else []) or []),
        iac_systems=iac_systems,
        sandbox=sandbox,
        clone_path=state.get("clone_path"),
        summary=f"{state.get('repo_full_name')}@{state.get('commit_sha')}: {kinds}",
    )


def _workdir(state: IACState) -> Path | None:
    sandbox = state.get("sandbox") or {}
    path = sandbox.get("workdir") if isinstance(sandbox, dict) else None
    path = path or state.get("clone_path")
    return Path(path) if path else None


def _fail(state: IACState, message: str) -> dict[str, Any]:
    return {"status": _FAILED, "errors": [message]}
