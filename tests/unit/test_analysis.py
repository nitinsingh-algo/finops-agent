from __future__ import annotations

from pathlib import Path

from algo_finops.agents.iac.analysis.engine import RepositoryAnalysisEngine

FIXTURE = Path(__file__).parents[1] / "fixtures" / "sample-stack"


def test_engine_detects_iac_and_runtime(tmp_path: Path) -> None:
    engine = RepositoryAnalysisEngine()
    findings = engine.analyze(FIXTURE)
    kinds = {item.kind for item in findings}
    assert {"terraform", "docker", "kubernetes", "helm", "runtime"} <= kinds
    runtime = next(item for item in findings if item.kind == "runtime")
    assert "node" in runtime.metadata["languages"]


def test_engine_can_register_a_custom_analyzer(tmp_path: Path) -> None:
    class MarkerAnalyzer:
        name = "marker"

        def detect(self, index) -> bool:
            return True

        def analyze(self, index):
            from algo_finops.agents.iac.domain import AnalyzerFinding

            return AnalyzerFinding(analyzer=self.name, kind="marker", metadata={"files": len(index.files)})

    engine = RepositoryAnalysisEngine(analyzers=[])
    engine.register(MarkerAnalyzer())
    findings = engine.analyze(FIXTURE)
    assert findings[0].kind == "marker"
