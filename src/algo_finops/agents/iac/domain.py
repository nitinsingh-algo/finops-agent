from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class IACError(Exception):
    """Base error for the IAC agent. Nodes convert these into state.errors."""


class WebhookVerificationError(IACError):
    pass


class TokenResolutionError(IACError):
    pass


class CloneError(IACError):
    pass


class SandboxError(IACError):
    pass


class IaCKind(str, Enum):
    TERRAFORM = "terraform"
    TERRAGRUNT = "terragrunt"
    PULUMI = "pulumi"
    CDK = "cdk"
    CLOUDFORMATION = "cloudformation"
    KUBERNETES = "kubernetes"
    HELM = "helm"
    ANSIBLE = "ansible"
    DOCKER = "docker"
    COMPOSE = "compose"
    BICEP = "bicep"
    RUNTIME = "runtime"


class GitHubEvent(BaseModel):
    delivery_id: str
    event_name: str
    installation_id: int | None = None
    repo_full_name: str
    clone_url: str
    default_branch: str = "main"
    ref: str | None = None
    commit_sha: str | None = None
    sender: str | None = None
    action: str | None = None


class CloneResult(BaseModel):
    run_id: str
    path: str
    commit_sha: str
    branch: str
    isolated: bool = True


class SandboxHandle(BaseModel):
    sandbox_id: str
    provider: str
    workdir: str
    metadata: dict[str, str] = Field(default_factory=dict)


class AnalyzerFinding(BaseModel):
    analyzer: str
    kind: str
    confidence: float = 1.0
    root_paths: list[str] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    follow_up: list[str] = Field(
        default_factory=list,
        description="Analyzer names to run on the next engine pass.",
    )


class ProjectBlueprint(BaseModel):
    """Stable contract later plan/apply stages consume. Do not couple those stages to git internals."""

    run_id: str
    repo_full_name: str
    commit_sha: str
    languages: list[str] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    iac_systems: list[AnalyzerFinding] = Field(default_factory=list)
    sandbox: SandboxHandle | None = None
    clone_path: str | None = None
    summary: str = ""
