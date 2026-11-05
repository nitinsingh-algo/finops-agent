from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from algo_finops.agents.iac.domain import GitHubEvent, ProjectBlueprint
from algo_finops.persistence.models import PipelineRun


class SqlRunStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def create(self, run_id: str, event: GitHubEvent) -> None:
        async with self._sessions() as session:
            existing = await session.get(PipelineRun, run_id)
            if existing is not None:
                return
            session.add(
                PipelineRun(
                    id=run_id,
                    delivery_id=event.delivery_id,
                    event_name=event.event_name,
                    repo_full_name=event.repo_full_name,
                    commit_sha=event.commit_sha or "",
                    status="received",
                )
            )
            await session.commit()

    async def get(self, run_id: str) -> dict[str, Any] | None:
        async with self._sessions() as session:
            row = await session.get(PipelineRun, run_id)
            return _row_to_dict(row)

    async def get_by_delivery(self, delivery_id: str) -> dict[str, Any] | None:
        async with self._sessions() as session:
            from sqlalchemy import select

            result = await session.execute(select(PipelineRun).where(PipelineRun.delivery_id == delivery_id))
            return _row_to_dict(result.scalar_one_or_none())

    async def mark(
        self,
        run_id: str,
        *,
        status: str,
        blueprint: ProjectBlueprint | None = None,
        error: str | None = None,
    ) -> None:
        async with self._sessions() as session:
            row = await session.get(PipelineRun, run_id)
            if row is None:
                return
            row.status = status
            if blueprint is not None:
                row.blueprint_json = blueprint.model_dump_json()
                row.commit_sha = blueprint.commit_sha
            if error is not None:
                row.error = error
            await session.commit()


def _row_to_dict(row: PipelineRun | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "id": row.id,
        "delivery_id": row.delivery_id,
        "status": row.status,
        "repo_full_name": row.repo_full_name,
        "commit_sha": row.commit_sha,
        "blueprint_json": row.blueprint_json,
        "error": row.error,
    }
