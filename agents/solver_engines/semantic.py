from __future__ import annotations

from agents.models import SolverRequest
from agents.solver_engines.base import SolverEngine
from llm_engine import (
    generate_initial_payloads,
    mutate_payloads,
)


class SemanticSolver(SolverEngine):
    dimension = "semantic"

    def __init__(self, concurrency: int = 5, timeout: int = 15, model: str = "mimo-v2.5-pro"):
        super().__init__(concurrency=concurrency, timeout=timeout)
        self.model = model

    def generate(self, request: SolverRequest) -> list[str]:
        if request.round_num == 0:
            result = generate_initial_payloads(
                vuln_type=request.target.vuln_type,
                target_url=request.target.url,
                model=self.model,
                kb_context=request.kb_context,
            )
        else:
            result = mutate_payloads(
                failed_payloads=request.blocked_payloads,
                vuln_type=request.target.vuln_type,
                target_url=request.target.url,
                model=self.model,
                kb_context=request.kb_context,
                force_strategy_change=False,
            )

        return result.get("payloads", [])
