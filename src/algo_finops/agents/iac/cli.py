from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
from uuid import uuid4

from cryptography.fernet import Fernet

from algo_finops.agents.iac.adapters.clone import LocalCopyCloner
from algo_finops.agents.iac.adapters.github import event_to_state
from algo_finops.agents.iac.domain import GitHubEvent
from algo_finops.agents.iac.graph import build_iac_graph
from algo_finops.agents.iac.runtime import build_runtime
from algo_finops.config import Settings, get_settings
from algo_finops.persistence.session import init_db


def main() -> None:
    parser = argparse.ArgumentParser(prog="iac", description="IAC LangGraph sub-agent")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the GitHub webhook server")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)

    analyze = sub.add_parser("analyze", help="Run step-1 ingest against a local directory")
    analyze.add_argument("path", type=Path)
    analyze.add_argument("--repo", default="local/sample")

    sub.add_parser("gen-key", help="Generate IAC_TOKEN_ENCRYPTION_KEY")

    args = parser.parse_args()
    if args.command == "serve":
        _serve(args.host, args.port)
    elif args.command == "analyze":
        asyncio.run(_analyze(args.path, args.repo))
    elif args.command == "gen-key":
        print(Fernet.generate_key().decode("utf-8"))


def _serve(host: str | None, port: int | None) -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "algo_finops.agents.iac.api:app",
        host=host or settings.host,
        port=port or settings.port,
        log_level=settings.log_level.lower(),
    )


class _StaticTokenStore:
    async def resolve(self, event: GitHubEvent) -> str:
        return "local-dev-token"


async def _analyze(path: Path, repo: str) -> None:
    if not path.is_dir():
        raise SystemExit(f"Not a directory: {path}")
    logging.basicConfig(level=logging.INFO)
    settings = Settings(
        github_token="local-dev-token",
        token_encryption_key=Fernet.generate_key().decode("utf-8"),
        database_url="sqlite+aiosqlite:///./iac.db",
        workspace_root=Path("./.workspaces"),
        sandbox_provider="local",
    )
    factory, engine = await init_db(settings.database_url)
    try:
        runtime = build_runtime(
            settings,
            factory,
            cloner=LocalCopyCloner(path, settings),
            tokens=_StaticTokenStore(),
        )
        graph = build_iac_graph(runtime)
        event = GitHubEvent(
            delivery_id=str(uuid4()),
            event_name="push",
            repo_full_name=repo,
            clone_url="https://github.com/local/sample.git",
            commit_sha="local",
            ref="main",
        )
        run_id = str(uuid4())
        result = await graph.ainvoke(
            {
                "run_id": run_id,
                "status": "received",
                "findings": [],
                "errors": [],
                **event_to_state(event),
            }
        )
        print(json.dumps(result.get("blueprint") or {"status": result.get("status"), "errors": result.get("errors")}, indent=2))
    finally:
        await engine.dispose()
