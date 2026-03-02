"""Base validator interface."""
from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseValidator(ABC):
    def __init__(self, credential: str, meta: Dict[str, Any]):
        self.credential = credential
        self.meta       = meta

    @abstractmethod
    def validate(self) -> Dict[str, Any]:
        """
        Call provider APIs to check if credential is active.
        Returns a result dict with at minimum: valid, identity, error.
        """
        ...

    def enumerate(self, result: Dict[str, Any]) -> None:
        """
        Enrich result with permissions list and blast_radius assessment.
        Default is a no-op; providers override as needed.
        """
        result.setdefault("permissions", [])
        result.setdefault("blast_radius", {})
