from dataclasses import dataclass, field

@dataclass
class VerifyResult:
    status: str                 # verified | refuted | unverifiable
    confidence: float
    summary: str
    detail: str = ""
    kind: str = "scan"
    tokens: int = 0
    seconds: float = 0.0

class ToolMissing(RuntimeError):
    """Raised when a required external tool is not installed. Never silently skipped."""
