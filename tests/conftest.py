from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

from algo_finops.agents.iac.adapters.clone import LocalCopyCloner
from algo_finops.agents.iac.adapters.sandbox import LocalSandbox
from algo_finops.agents.iac.analysis.engine import RepositoryAnalysisEngine
from algo_finops.agents.iac.domain import GitHubEvent, ProjectBlueprint
from algo_finops.agents.iac.runtime import IACRuntime
from algo_finops.config import Settings

FIXTURE_STACK = Path(__file__).parent / "fixtures" / "sample-stack"


@dataclass
class InMemoryRunStore:
    rows: dict[str, dict[str, Any]] = field(default_factory=dict)

    async def create(self, run_id: str, event: GitHubEvent) -> None:
        self.rows.setdefault(
            run_id,
            {
                "id": run_id,
                "delivery_id": event.delivery_id,
                "status": "received",
                "repo_full_name": event.repo_full_name,
                "commit_sha": event.commit_sha or "",
                "blueprint_json": None,
                "error": None,
            },
        )

    async def get(self, run_id: str) -> dict[str, Any] | None:
        return self.rows.get(run_id)

    async def get_by_delivery(self, delivery_id: str) -> dict[str, Any] | None:
        for row in self.rows.values():
            if row["delivery_id"] == delivery_id:
                return row
        return None

    async def mark(
        self,
        run_id: str,
        *,
        status: str,
        blueprint: ProjectBlueprint | None = None,
        error: str | None = None,
    ) -> None:
        row = self.rows.setdefault(run_id, {"id": run_id, "delivery_id": run_id})
        row["status"] = status
        if blueprint is not None:
            row["blueprint_json"] = blueprint.model_dump_json()
        if error is not None:
            row["error"] = error


class StaticTokenStore:
    def __init__(self, token: str = "test-token") -> None:
        self.token = token
        self.calls = 0

    async def resolve(self, event: GitHubEvent) -> str:
        self.calls += 1
        return self.token


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        github_webhook_secret="test-secret",
        github_token="test-token",
        token_encryption_key=Fernet.generate_key().decode("utf-8"),
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iac.db'}",
        workspace_root=tmp_path / "workspaces",
        sandbox_provider="local",
    )


@pytest.fixture
def runtime(settings: Settings) -> IACRuntime:
    return IACRuntime(
        settings=settings,
        tokens=StaticTokenStore(),
        cloner=LocalCopyCloner(FIXTURE_STACK, settings),
        sandbox=LocalSandbox(settings),
        analysis=RepositoryAnalysisEngine(),
        runs=InMemoryRunStore(),
    )
