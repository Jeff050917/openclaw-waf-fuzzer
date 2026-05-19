from __future__ import annotations

from agents.models import SolverRequest, RawResponse
from agents.solver_engines.base import SolverEngine
from agents.solver_engines.semantic import SemanticSolver
from agents.solver_engines.protocol import ProtocolSolver
from agents.solver_engines.performance import PerfSolver
from agents.solver_engines.topology import TopologySolver


class Solver:
    def __init__(self, concurrency: int = 5, timeout: int = 15, model: str = "mimo-v2.5-pro"):
        self._engines: dict[str, SolverEngine] = {
            "semantic": SemanticSolver(concurrency=concurrency, timeout=timeout, model=model),
            "protocol": ProtocolSolver(concurrency=concurrency, timeout=timeout, model=model),
            "performance": PerfSolver(concurrency=concurrency, timeout=timeout, model=model),
            "topology": TopologySolver(concurrency=concurrency, timeout=timeout, model=model),
        }

    def solve(self, request: SolverRequest) -> list[RawResponse]:
        engine = self._engines.get(request.dimension)
        if not engine:
            raise ValueError(f"Unknown dimension: {request.dimension}")
        payloads = engine.generate(request)
        if not payloads:
            return []
        return engine.send(payloads, request)
