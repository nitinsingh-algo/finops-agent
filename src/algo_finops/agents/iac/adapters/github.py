from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from algo_finops.agents.iac.domain import GitHubEvent, WebhookVerificationError

_SUPPORTED_EVENTS = frozenset({"push", "pull_request", "ping", "workflow_dispatch"})


def verify_signature(*, secret: str, payload: bytes, signature_header: str | None) -> None:
    if not secret:
        raise WebhookVerificationError("IAC_GITHUB_WEBHOOK_SECRET is not configured")
    if not signature_header:
        raise WebhookVerificationError("Missing X-Hub-Signature-256 header")
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    expected = f"sha256={digest}"
    if not hmac.compare_digest(expected, signature_header):
        raise WebhookVerificationError("Invalid GitHub webhook signature")


def parse_event(*, delivery_id: str, event_name: str, payload: bytes) -> GitHubEvent:
    if event_name not in _SUPPORTED_EVENTS:
        raise WebhookVerificationError(f"Unsupported GitHub event: {event_name}")
    try:
        body: dict[str, Any] = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebhookVerificationError("Webhook payload is not valid JSON") from exc

    if event_name == "ping":
        repo = body.get("repository") or {}
        return GitHubEvent(
            delivery_id=delivery_id,
            event_name=event_name,
            installation_id=_installation_id(body),
            repo_full_name=repo.get("full_name") or "ping",
            clone_url=repo.get("clone_url") or "",
            default_branch=repo.get("default_branch") or "main",
            sender=(body.get("sender") or {}).get("login"),
        )

    repo = body.get("repository") or {}
    full_name = repo.get("full_name")
    clone_url = repo.get("clone_url")
    if not full_name or not clone_url:
        raise WebhookVerificationError("Webhook payload is missing repository.clone_url")

    ref, sha = _ref_and_sha(event_name, body, repo)
    return GitHubEvent(
        delivery_id=delivery_id,
        event_name=event_name,
        installation_id=_installation_id(body),
        repo_full_name=full_name,
        clone_url=clone_url,
        default_branch=repo.get("default_branch") or "main",
        ref=ref,
        commit_sha=sha,
        sender=(body.get("sender") or {}).get("login"),
        action=body.get("action"),
    )


def event_to_state(event: GitHubEvent) -> dict[str, Any]:
    return {
        "delivery_id": event.delivery_id,
        "event_name": event.event_name,
        "installation_id": event.installation_id,
        "repo_full_name": event.repo_full_name,
        "clone_url": event.clone_url,
        "default_branch": event.default_branch,
        "ref": event.ref,
        "commit_sha": event.commit_sha,
    }


def state_to_event(state: dict[str, Any]) -> GitHubEvent:
    return GitHubEvent(
        delivery_id=state["delivery_id"],
        event_name=state["event_name"],
        installation_id=state.get("installation_id"),
        repo_full_name=state.get("repo_full_name") or "",
        clone_url=state.get("clone_url") or "",
        default_branch=state.get("default_branch") or "main",
        ref=state.get("ref"),
        commit_sha=state.get("commit_sha"),
    )


def _installation_id(body: dict[str, Any]) -> int | None:
    raw = (body.get("installation") or {}).get("id")
    return int(raw) if raw is not None else None


def _ref_and_sha(event_name: str, body: dict[str, Any], repo: dict[str, Any]) -> tuple[str | None, str | None]:
    if event_name == "pull_request":
        head = (body.get("pull_request") or {}).get("head") or {}
        return head.get("ref") or repo.get("default_branch"), head.get("sha")
    if event_name == "workflow_dispatch":
        return body.get("ref") or repo.get("default_branch"), None
    after = body.get("after")
    if after == "0000000000000000000000000000000000000000":
        after = None
    return body.get("ref") or repo.get("default_branch"), after
