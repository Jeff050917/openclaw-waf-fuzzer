from __future__ import annotations
from abc import ABC, abstractmethod
from agents.models import SolverRequest, RawResponse


class SolverEngine(ABC):
    @abstractmethod
    def generate(self, request: SolverRequest) -> list[str]:
        """Generate payloads for the given request."""
        ...

    @abstractmethod
    def send(self, payloads: list[str], request: SolverRequest) -> list[RawResponse]:
        """Send payloads and return raw responses."""
        ...
