from __future__ import annotations

from typing import Any
from uuid import uuid4

from algo_finops.agents.iac.domain import GitHubEvent


def make_event(**overrides: Any) -> GitHubEvent:
    payload = dict(
        delivery_id=str(uuid4()),
        event_name="push",
        installation_id=42,
        repo_full_name="acme/demo",
        clone_url="https://github.com/acme/demo.git",
        default_branch="main",
        ref="refs/heads/main",
        commit_sha="abc123",
    )
    payload.update(overrides)
    return GitHubEvent.model_validate(payload)
