from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from algo_finops.agents.iac.adapters.clone import IsolatedGitCloner
from algo_finops.agents.iac.adapters.runs import SqlRunStore
from algo_finops.agents.iac.adapters.sandbox import build_sandbox
from algo_finops.agents.iac.adapters.tokens import FernetCipher, GithubTokenStore
from algo_finops.agents.iac.analysis.engine import RepositoryAnalysisEngine
from algo_finops.agents.iac.ports import AnalysisEngine, RepoCloner, RunStore, SandboxProvider, TokenStore
from algo_finops.config import Settings


@dataclass(slots=True)
class IACRuntime:
    """Composition root. Graph nodes close over this; adapters stay replaceable in tests."""

    settings: Settings
    tokens: TokenStore
    cloner: RepoCloner
    sandbox: SandboxProvider
    analysis: AnalysisEngine
    runs: RunStore


def build_runtime(
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
    *,
    cloner: RepoCloner | None = None,
    sandbox: SandboxProvider | None = None,
    analysis: AnalysisEngine | None = None,
    tokens: TokenStore | None = None,
    runs: RunStore | None = None,
) -> IACRuntime:
    cipher = FernetCipher(settings.token_encryption_key) if settings.token_encryption_key else None
    return IACRuntime(
        settings=settings,
        tokens=tokens or GithubTokenStore(settings, session_factory, cipher=cipher),
        cloner=cloner or IsolatedGitCloner(settings),
        sandbox=sandbox or build_sandbox(settings),
        analysis=analysis or RepositoryAnalysisEngine(max_files=settings.max_index_files),
        runs=runs or SqlRunStore(session_factory),
    )
