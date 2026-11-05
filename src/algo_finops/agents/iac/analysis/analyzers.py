from __future__ import annotations

from pathlib import Path
from typing import Protocol

from algo_finops.agents.iac.analysis.tree import FileIndex
from algo_finops.agents.iac.domain import AnalyzerFinding, IaCKind


class Analyzer(Protocol):
    name: str

    def detect(self, index: FileIndex) -> bool: ...

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None: ...


class TerraformAnalyzer:
    name = "terraform"

    def detect(self, index: FileIndex) -> bool:
        return bool(index.glob_suffix(".tf", ".tfvars") or index.named(".terraform.lock.hcl"))

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None:
        tf_files = index.glob_suffix(".tf")
        backends = [path for path in tf_files if Path(path).name == "backend.tf"]
        return AnalyzerFinding(
            analyzer=self.name,
            kind=IaCKind.TERRAFORM.value,
            confidence=0.95,
            root_paths=_unique_roots(tf_files),
            entrypoints=[path for path in tf_files if Path(path).name == "main.tf"] or tf_files[:5],
            metadata={
                "tf_files": len(tf_files),
                "tfvars": len(index.glob_suffix(".tfvars")),
                "has_backend": bool(backends),
                "lockfile": bool(index.named(".terraform.lock.hcl")),
            },
        )


class TerragruntAnalyzer:
    name = "terragrunt"

    def detect(self, index: FileIndex) -> bool:
        return bool(index.named("terragrunt.hcl"))

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None:
        files = index.named("terragrunt.hcl")
        return AnalyzerFinding(
            analyzer=self.name,
            kind=IaCKind.TERRAGRUNT.value,
            root_paths=_unique_roots(files),
            entrypoints=files[:10],
            metadata={"units": len(files)},
            follow_up=["terraform"] if not index.glob_suffix(".tf") else [],
        )


class PulumiAnalyzer:
    name = "pulumi"

    def detect(self, index: FileIndex) -> bool:
        return bool(index.named("pulumi.yaml", "pulumi.yml"))

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None:
        files = index.named("pulumi.yaml", "pulumi.yml")
        return AnalyzerFinding(
            analyzer=self.name,
            kind=IaCKind.PULUMI.value,
            root_paths=_unique_roots(files),
            entrypoints=files,
            metadata={"projects": len(files)},
        )


class CdkAnalyzer:
    name = "cdk"

    def detect(self, index: FileIndex) -> bool:
        return bool(index.named("cdk.json", "cdk.context.json"))

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None:
        files = index.named("cdk.json")
        return AnalyzerFinding(
            analyzer=self.name,
            kind=IaCKind.CDK.value,
            root_paths=_unique_roots(files),
            entrypoints=files,
        )


class CloudFormationAnalyzer:
    name = "cloudformation"

    def detect(self, index: FileIndex) -> bool:
        return any("AWSTemplateFormatVersion" in index.read(path) for path in _yaml_candidates(index)[:40])

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None:
        templates = [path for path in _yaml_candidates(index) if "AWSTemplateFormatVersion" in index.read(path)]
        if not templates:
            return None
        return AnalyzerFinding(
            analyzer=self.name,
            kind=IaCKind.CLOUDFORMATION.value,
            root_paths=_unique_roots(templates),
            entrypoints=templates[:10],
            metadata={"templates": len(templates)},
        )


class KubernetesAnalyzer:
    name = "kubernetes"

    def detect(self, index: FileIndex) -> bool:
        return any(_looks_like_k8s(index.read(path)) for path in _yaml_candidates(index)[:60])

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None:
        manifests = [path for path in _yaml_candidates(index) if _looks_like_k8s(index.read(path))]
        if not manifests:
            return None
        kinds: dict[str, int] = {}
        for path in manifests[:40]:
            kind = _yaml_field(index.read(path), "kind")
            if kind:
                kinds[kind] = kinds.get(kind, 0) + 1
        return AnalyzerFinding(
            analyzer=self.name,
            kind=IaCKind.KUBERNETES.value,
            confidence=0.85,
            root_paths=_unique_roots(manifests),
            entrypoints=manifests[:15],
            metadata={"manifests": len(manifests), "kinds": kinds},
        )


class HelmAnalyzer:
    name = "helm"

    def detect(self, index: FileIndex) -> bool:
        return bool(index.named("chart.yaml"))

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None:
        charts = index.named("chart.yaml")
        return AnalyzerFinding(
            analyzer=self.name,
            kind=IaCKind.HELM.value,
            root_paths=_unique_roots(charts),
            entrypoints=charts,
            metadata={"charts": len(charts)},
        )


class AnsibleAnalyzer:
    name = "ansible"

    def detect(self, index: FileIndex) -> bool:
        return bool(index.named("ansible.cfg", "playbook.yml", "playbook.yaml", "site.yml", "site.yaml"))

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None:
        entry = index.named("playbook.yml", "playbook.yaml", "site.yml", "site.yaml")
        return AnalyzerFinding(
            analyzer=self.name,
            kind=IaCKind.ANSIBLE.value,
            root_paths=_unique_roots(entry or index.named("ansible.cfg")),
            entrypoints=entry[:10],
        )


class DockerAnalyzer:
    name = "docker"

    def detect(self, index: FileIndex) -> bool:
        return bool(index.named("dockerfile", "containerfile") or index.glob_suffix(".dockerfile"))

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None:
        files = index.named("dockerfile", "containerfile") + index.glob_suffix(".dockerfile")
        return AnalyzerFinding(
            analyzer=self.name,
            kind=IaCKind.DOCKER.value,
            root_paths=_unique_roots(files),
            entrypoints=files,
        )


class ComposeAnalyzer:
    name = "compose"

    def detect(self, index: FileIndex) -> bool:
        return bool(index.named("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"))

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None:
        files = index.named("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
        return AnalyzerFinding(
            analyzer=self.name,
            kind=IaCKind.COMPOSE.value,
            root_paths=_unique_roots(files),
            entrypoints=files,
        )


class BicepAnalyzer:
    name = "bicep"

    def detect(self, index: FileIndex) -> bool:
        return bool(index.glob_suffix(".bicep"))

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None:
        files = index.glob_suffix(".bicep")
        return AnalyzerFinding(
            analyzer=self.name,
            kind=IaCKind.BICEP.value,
            root_paths=_unique_roots(files),
            entrypoints=[path for path in files if Path(path).name == "main.bicep"] or files[:5],
        )


class RuntimeAnalyzer:
    name = "runtime"

    def detect(self, index: FileIndex) -> bool:
        return bool(_runtime_hits(index))

    def analyze(self, index: FileIndex) -> AnalyzerFinding | None:
        hits = _runtime_hits(index)
        languages = sorted({lang for lang, _ in hits})
        managers = sorted({manager for _, manager in hits if manager})
        return AnalyzerFinding(
            analyzer=self.name,
            kind=IaCKind.RUNTIME.value,
            confidence=0.9,
            root_paths=["."],
            metadata={"languages": languages, "package_managers": managers},
        )


def default_analyzers() -> list[Analyzer]:
    return [
        TerraformAnalyzer(),
        TerragruntAnalyzer(),
        PulumiAnalyzer(),
        CdkAnalyzer(),
        CloudFormationAnalyzer(),
        KubernetesAnalyzer(),
        HelmAnalyzer(),
        AnsibleAnalyzer(),
        DockerAnalyzer(),
        ComposeAnalyzer(),
        BicepAnalyzer(),
        RuntimeAnalyzer(),
    ]


def _runtime_hits(index: FileIndex) -> list[tuple[str, str]]:
    mapping = (
        (("pyproject.toml", "requirements.txt", "Pipfile"), "python", "pip"),
        (("package.json",), "node", "npm"),
        (("pnpm-lock.yaml",), "node", "pnpm"),
        (("yarn.lock",), "node", "yarn"),
        (("go.mod",), "go", "go"),
        (("cargo.toml",), "rust", "cargo"),
        (("pom.xml",), "java", "maven"),
        (("build.gradle", "build.gradle.kts"), "java", "gradle"),
        (("composer.json",), "php", "composer"),
        (("gemfile",), "ruby", "bundler"),
    )
    hits: list[tuple[str, str]] = []
    for names, language, manager in mapping:
        if index.named(*names):
            hits.append((language, manager))
    return hits


def _yaml_candidates(index: FileIndex) -> list[str]:
    return index.glob_suffix(".yml", ".yaml")


def _looks_like_k8s(text: str) -> bool:
    return "apiVersion:" in text and "kind:" in text and "AWSTemplateFormatVersion" not in text


def _yaml_field(text: str, field: str) -> str | None:
    prefix = f"{field}:"
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split(":", 1)[1].strip()
    return None


def _unique_roots(paths: list[str]) -> list[str]:
    roots: list[str] = []
    seen: set[str] = set()
    for path in paths:
        parent = str(Path(path).parent)
        parent = "." if parent == "." else parent
        if parent not in seen:
            seen.add(parent)
            roots.append(parent)
    return roots
