from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path
from urllib.parse import urlparse

from algo_finops.agents.iac.domain import CloneError, CloneResult, GitHubEvent
from algo_finops.config import Settings

_ALLOWED_HOSTS = frozenset({"github.com", "www.github.com"})


class IsolatedGitCloner:
    """Shallow-clones into a per-run directory. Credentials are passed via git http headers, never URLs."""

    def __init__(self, settings: Settings) -> None:
        self._root = settings.workspace_root.expanduser().resolve()
        self._depth = settings.clone_depth

    async def clone(self, event: GitHubEvent, token: str, run_id: str) -> CloneResult:
        dest = self._workspace(run_id)
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, mode=0o700)

        clone_url = _public_https_url(event.clone_url)
        branch = _branch_from_ref(event.ref) or event.default_branch
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}
        git = ["git", "-c", f"http.extraHeader=Authorization: Bearer {token}"]
        try:
            await _git(
                [*git, "clone", "--depth", str(self._depth), "--single-branch", "--branch", branch, clone_url, str(dest)],
                env=env,
                token=token,
            )
            sha = event.commit_sha
            if sha:
                await _git([*git, "fetch", "--depth", "1", "origin", sha], cwd=dest, env=env, token=token)
                await _git(["git", "checkout", "--force", sha], cwd=dest, env=env, token=token)
            else:
                sha = (await _git(["git", "rev-parse", "HEAD"], cwd=dest, env=env, token=token)).strip()
            await _git(["git", "remote", "set-url", "origin", clone_url], cwd=dest, env=env, token=token)
        except Exception:
            shutil.rmtree(dest, ignore_errors=True)
            raise

        return CloneResult(run_id=run_id, path=str(dest), commit_sha=sha, branch=branch, isolated=True)

    def _workspace(self, run_id: str) -> Path:
        if "/" in run_id or ".." in run_id:
            raise CloneError("Invalid run_id")
        self._root.mkdir(parents=True, exist_ok=True)
        return self._root / run_id


class LocalCopyCloner:
    """Test/dev cloner that copies a local tree into the isolated workspace."""

    def __init__(self, source: Path, settings: Settings) -> None:
        self._source = source
        self._root = settings.workspace_root.expanduser().resolve()

    async def clone(self, event: GitHubEvent, token: str, run_id: str) -> CloneResult:
        dest = self._root / run_id
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(self._source, dest)
        dest.chmod(0o700)
        return CloneResult(
            run_id=run_id,
            path=str(dest),
            commit_sha=event.commit_sha or "local",
            branch=_branch_from_ref(event.ref) or event.default_branch,
            isolated=True,
        )


def _public_https_url(clone_url: str) -> str:
    parsed = urlparse(clone_url)
    if parsed.scheme == "git" and parsed.netloc == "github.com":
        path = parsed.path.removeprefix("/").removesuffix(".git")
        return f"https://github.com/{path}.git"
    if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS:
        raise CloneError("Only https://github.com clone URLs are allowed")
    path = parsed.path if parsed.path.endswith(".git") else f"{parsed.path}.git"
    return f"https://github.com{path}"


def _branch_from_ref(ref: str | None) -> str | None:
    if not ref:
        return None
    for prefix in ("refs/heads/", "refs/tags/"):
        if ref.startswith(prefix):
            return ref[len(prefix) :]
    return ref


async def _git(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str], token: str) -> str:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        message = (stderr or stdout).decode("utf-8", errors="replace")[-2000:]
        raise CloneError(_redact(message, token) or "git command failed")
    return stdout.decode("utf-8", errors="replace")


def _redact(text: str, token: str) -> str:
    if token:
        text = text.replace(token, "***")
    return text.replace("Authorization: Bearer ***", "Authorization: Bearer ***")
