from __future__ import annotations

from typing import Protocol

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from algo_finops.agents.iac.nodes import (
    IACNodes,
    route_after_analyze,
    route_after_ingest,
    route_if_healthy,
)
from algo_finops.agents.iac.runtime import IACRuntime
from algo_finops.agents.iac.state import IACState


class GraphStage(Protocol):
    """A pipeline slice that can be registered onto the IAC graph.

    Step 1 is IngestStage. Later plan/apply stages implement the same contract
    and are appended to `build_iac_graph(stages=[IngestStage(), PlanStage(), ...])`.
    """

    name: str

    def entry(self) -> str: ...

    def register(self, graph: StateGraph, nodes: IACNodes, *, on_complete: str) -> None: ...


class IngestStage:
    """Webhook → token → isolated clone → sandbox → analyze ↔ lightweight engine."""

    name = "ingest"

    def entry(self) -> str:
        return "ingest_webhook"

    def register(self, graph: StateGraph, nodes: IACNodes, *, on_complete: str) -> None:
        graph.add_node("ingest_webhook", nodes.ingest_webhook)
        graph.add_node("resolve_token", nodes.resolve_token)
        graph.add_node("clone_repository", nodes.clone_repository)
        graph.add_node("prepare_sandbox", nodes.prepare_sandbox)
        graph.add_node("analyze_project_structure", nodes.analyze_project_structure)
        graph.add_node("run_analysis_engine", nodes.run_analysis_engine)

        graph.add_conditional_edges(
            "ingest_webhook",
            route_after_ingest,
            {"resolve_token": "resolve_token", "__end__": END},
        )
        graph.add_conditional_edges(
            "resolve_token",
            route_if_healthy("clone_repository"),
            {"clone_repository": "clone_repository", "__end__": END},
        )
        graph.add_conditional_edges(
            "clone_repository",
            route_if_healthy("prepare_sandbox"),
            {"prepare_sandbox": "prepare_sandbox", "__end__": END},
        )
        graph.add_conditional_edges(
            "prepare_sandbox",
            route_if_healthy("analyze_project_structure"),
            {"analyze_project_structure": "analyze_project_structure", "__end__": END},
        )
        completion_map = {
            "run_analysis_engine": "run_analysis_engine",
            "__end__": END,
        }
        if on_complete != END:
            completion_map[on_complete] = on_complete
        graph.add_conditional_edges(
            "analyze_project_structure",
            route_after_analyze(on_complete),
            completion_map,
        )
        graph.add_edge("run_analysis_engine", "analyze_project_structure")


def build_iac_graph(
    runtime: IACRuntime,
    *,
    stages: list[GraphStage] | None = None,
    checkpointer: InMemorySaver | None = None,
):
    """Compile the IAC sub-agent.

    Compiled with `checkpointer=None` it can be attached as a LangGraph subgraph
    of a future supervisor agent and inherit that parent's checkpointer.
    """
    stages = list(stages or [IngestStage()])
    nodes = IACNodes(runtime)
    graph = StateGraph(IACState)

    entries = [stage.entry() for stage in stages]
    for index, stage in enumerate(stages):
        nxt = entries[index + 1] if index + 1 < len(stages) else END
        stage.register(graph, nodes, on_complete=nxt)

    graph.add_edge(START, stages[0].entry())
    return graph.compile(checkpointer=checkpointer, name="iac-agent")
