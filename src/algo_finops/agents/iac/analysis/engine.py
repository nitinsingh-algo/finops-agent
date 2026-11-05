from __future__ import annotations

import logging
from importlib.metadata import entry_points
from pathlib import Path

from algo_finops.agents.iac.analysis.analyzers import Analyzer, default_analyzers
from algo_finops.agents.iac.analysis.tree import build_index
from algo_finops.agents.iac.domain import AnalyzerFinding

logger = logging.getLogger(__name__)

_PLUGIN_GROUP = "algo_finops.iac.analyzers"


class RepositoryAnalysisEngine:
    """Lightweight, plugin-based scanner. New IaC kinds register without graph changes."""

    def __init__(
        self,
        analyzers: list[Analyzer] | None = None,
        *,
        max_files: int = 20_000,
        load_plugins: bool | None = None,
    ) -> None:
        if analyzers is None:
            self._analyzers = {analyzer.name: analyzer for analyzer in default_analyzers()}
            load_plugins = True if load_plugins is None else load_plugins
        else:
            self._analyzers = {analyzer.name: analyzer for analyzer in analyzers}
            load_plugins = False if load_plugins is None else load_plugins
        self._max_files = max_files
        if load_plugins:
            self._load_plugins()

    def register(self, analyzer: Analyzer) -> None:
        self._analyzers[analyzer.name] = analyzer

    def analyze(self, root: Path, only: list[str] | None = None) -> list[AnalyzerFinding]:
        index = build_index(root, max_files=self._max_files)
        selected = only or list(self._analyzers)
        findings: list[AnalyzerFinding] = []
        for name in selected:
            analyzer = self._analyzers.get(name)
            if analyzer is None:
                logger.debug("Skipping unknown analyzer %s", name)
                continue
            try:
                if not analyzer.detect(index):
                    continue
                finding = analyzer.analyze(index)
            except Exception:
                logger.exception("Analyzer %s failed", name)
                continue
            if finding is not None:
                findings.append(finding)
        return findings

    def _load_plugins(self) -> None:
        try:
            discovered = entry_points(group=_PLUGIN_GROUP)
        except Exception:
            return
        for entry in discovered:
            if entry.name in self._analyzers:
                continue
            try:
                loaded = entry.load()
                analyzer = loaded() if isinstance(loaded, type) else loaded
                self._analyzers[analyzer.name] = analyzer
            except Exception:
                logger.exception("Failed to load analyzer plugin %s", entry.name)
