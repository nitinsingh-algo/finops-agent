from __future__ import annotations

import asyncio
import logging
import shutil
import uuid
from pathlib import Path

from algo_finops.agents.iac.domain import CloneResult, SandboxError, SandboxHandle
from algo_finops.config import Settings

logger = logging.getLogger(__name__)


class LocalSandbox:
    """Filesystem isolation for analysis. Swap for DockerSandbox without touching the graph."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def create(self, clone: CloneResult) -> SandboxHandle:
        workdir = Path(clone.path)
        if not workdir.is_dir():
            raise SandboxError(f"Clone path does not exist: {clone.path}")
        return SandboxHandle(
            sandbox_id=f"local-{clone.run_id}",
            provider="local",
            workdir=str(workdir),
            metadata={"network": "none", "writable": "true"},
        )

    async def destroy(self, handle: SandboxHandle) -> None:
        workdir = Path(handle.workdir)
        if workdir.exists() and _is_workspace(workdir, self._settings.workspace_root):
            shutil.rmtree(workdir, ignore_errors=True)


class DockerSandbox:
    def __init__(self, settings: Settings) -> None:
        self._image = settings.sandbox_image
        self._settings = settings

    async def create(self, clone: CloneResult) -> SandboxHandle:
        sandbox_id = f"iac-{clone.run_id}-{uuid.uuid4().hex[:8]}"
        cmd = [
            "docker",
            "run",
            "-d",
            "--name",
            sandbox_id,
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "-v",
            f"{clone.path}:/workspace:ro",
            "-w",
            "/workspace",
            self._image,
            "sleep",
            "infinity",
        ]
        await _run(cmd)
        return SandboxHandle(
            sandbox_id=sandbox_id,
            provider="docker",
            workdir=clone.path,
            metadata={"container": sandbox_id, "network": "none", "mount": "ro"},
        )

    async def destroy(self, handle: SandboxHandle) -> None:
        await _run(["docker", "rm", "-f", handle.sandbox_id], check=False)


class AutoSandbox:
    def __init__(self, settings: Settings) -> None:
        self._docker = DockerSandbox(settings)
        self._local = LocalSandbox(settings)

    async def create(self, clone: CloneResult) -> SandboxHandle:
        if shutil.which("docker"):
            try:
                return await self._docker.create(clone)
            except SandboxError as exc:
                logger.warning("Docker sandbox unavailable (%s); using local isolation", exc)
        return await self._local.create(clone)

    async def destroy(self, handle: SandboxHandle) -> None:
        provider = self._docker if handle.provider == "docker" else self._local
        await provider.destroy(handle)


def build_sandbox(settings: Settings) -> LocalSandbox | DockerSandbox | AutoSandbox:
    if settings.sandbox_provider == "docker":
        return DockerSandbox(settings)
    if settings.sandbox_provider == "auto":
        return AutoSandbox(settings)
    return LocalSandbox(settings)


def _is_workspace(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.expanduser().resolve())
        return True
    except ValueError:
        return False


async def _run(cmd: list[str], *, check: bool = True) -> str:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if check and proc.returncode != 0:
        raise SandboxError((stderr or stdout).decode("utf-8", errors="replace")[-2000:] or "sandbox command failed")
    return stdout.decode("utf-8", errors="replace")
