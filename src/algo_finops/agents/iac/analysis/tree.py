from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        "target",
        "vendor",
        "__pycache__",
        ".terraform",
        ".pulumi",
        "coverage",
    }
)


@dataclass(slots=True)
class FileIndex:
    root: Path
    files: list[str]
    by_suffix: dict[str, list[str]] = field(default_factory=dict)
    by_name: dict[str, list[str]] = field(default_factory=dict)

    def glob_suffix(self, *suffixes: str) -> list[str]:
        found: list[str] = []
        for suffix in suffixes:
            found.extend(self.by_suffix.get(suffix.lower(), []))
        return found

    def named(self, *names: str) -> list[str]:
        found: list[str] = []
        for name in names:
            found.extend(self.by_name.get(name.lower(), []))
        return found

    def read(self, relative: str, limit: int = 8192) -> str:
        path = (self.root / relative).resolve()
        path.relative_to(self.root.resolve())
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)


def build_index(root: Path, *, max_files: int = 20_000) -> FileIndex:
    files: list[str] = []
    by_suffix: dict[str, list[str]] = {}
    by_name: dict[str, list[str]] = {}
    root = root.resolve()

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        rel = str(path.relative_to(root))
        files.append(rel)
        by_suffix.setdefault(path.suffix.lower(), []).append(rel)
        by_name.setdefault(path.name.lower(), []).append(rel)
        if len(files) >= max_files:
            break

    return FileIndex(root=root, files=files, by_suffix=by_suffix, by_name=by_name)
