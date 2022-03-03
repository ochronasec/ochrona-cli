import ast
from dataclasses import dataclass


@dataclass(eq=True, frozen=True)
class SASTViolation:
    node: ast.AST
    message: str
    location: str
    id: str
    severity: str
    confidence: str

    def todict(self):
        return {
            "message": self.message,
            "location": self.location,
            "id": self.id,
            "severity": self.severity,
            "confidence": self.confidence,
        }
