from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from algo_finops.agents.iac.adapters.github import parse_event, verify_signature
from algo_finops.agents.iac.domain import WebhookVerificationError


def _sign(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_verify_signature_accepts_valid_header() -> None:
    payload = b'{"ok": true}'
    verify_signature(secret="s3cret", payload=payload, signature_header=_sign("s3cret", payload))


def test_verify_signature_rejects_tampered_payload() -> None:
    with pytest.raises(WebhookVerificationError):
        verify_signature(
            secret="s3cret",
            payload=b'{"ok": false}',
            signature_header=_sign("s3cret", b'{"ok": true}'),
        )


def test_parse_push_event() -> None:
    body = json.dumps(
        {
            "after": "deadbeef",
            "ref": "refs/heads/main",
            "installation": {"id": 7},
            "repository": {
                "full_name": "acme/demo",
                "clone_url": "https://github.com/acme/demo.git",
                "default_branch": "main",
            },
            "sender": {"login": "octocat"},
        }
    ).encode()
    event = parse_event(delivery_id="d1", event_name="push", payload=body)
    assert event.repo_full_name == "acme/demo"
    assert event.commit_sha == "deadbeef"
    assert event.installation_id == 7


def test_parse_pull_request_uses_head_sha() -> None:
    body = json.dumps(
        {
            "action": "opened",
            "pull_request": {"head": {"ref": "feature", "sha": "cafebabe"}},
            "repository": {
                "full_name": "acme/demo",
                "clone_url": "https://github.com/acme/demo.git",
                "default_branch": "main",
            },
        }
    ).encode()
    event = parse_event(delivery_id="d2", event_name="pull_request", payload=body)
    assert event.commit_sha == "cafebabe"
    assert event.ref == "feature"


def test_unsupported_event_is_rejected() -> None:
    with pytest.raises(WebhookVerificationError):
        parse_event(delivery_id="d3", event_name="star", payload=b"{}")
