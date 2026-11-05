from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from algo_finops.agents.iac.domain import (
    AnalyzerFinding,
    CloneResult,
    GitHubEvent,
    ProjectBlueprint,
    SandboxHandle,
)


class TokenStore(Protocol):
    async def resolve(self, event: GitHubEvent) -> str:
        """Return a short-lived clone credential. Never persist the raw value in graph state."""


class RepoCloner(Protocol):
    async def clone(self, event: GitHubEvent, token: str, run_id: str) -> CloneResult: ...


class SandboxProvider(Protocol):
    async def create(self, clone: CloneResult) -> SandboxHandle: ...

    async def destroy(self, handle: SandboxHandle) -> None: ...


class AnalysisEngine(Protocol):
    def analyze(self, root: Path, only: list[str] | None = None) -> list[AnalyzerFinding]: ...


class RunStore(Protocol):
    async def create(self, run_id: str, event: GitHubEvent) -> None: ...

    async def get(self, run_id: str) -> dict[str, Any] | None: ...

    async def get_by_delivery(self, delivery_id: str) -> dict[str, Any] | None: ...

    async def mark(self, run_id: str, *, status: str, blueprint: ProjectBlueprint | None = None, error: str | None = None) -> None: ...
