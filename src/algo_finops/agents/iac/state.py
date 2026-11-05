from __future__ import annotations

from operator import add
from typing import Annotated, Any, NotRequired, TypedDict


class IACState(TypedDict):
    """Serializable LangGraph state. Tokens never live here — only installation/run ids."""

    run_id: str
    delivery_id: str
    event_name: str
    status: str
    findings: Annotated[list[dict[str, Any]], add]
    errors: Annotated[list[str], add]
    installation_id: NotRequired[int | None]
    repo_full_name: NotRequired[str]
    clone_url: NotRequired[str]
    default_branch: NotRequired[str]
    ref: NotRequired[str | None]
    commit_sha: NotRequired[str | None]
    clone_path: NotRequired[str | None]
    sandbox: NotRequired[dict[str, Any] | None]
    pending_analyzers: NotRequired[list[str]]
    blueprint: NotRequired[dict[str, Any] | None]
    token_ready: NotRequired[bool]
