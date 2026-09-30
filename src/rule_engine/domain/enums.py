from enum import Enum


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNABLE_TO_ASSESS = "UNABLE_TO_ASSESS"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"  # legal in schema; the engine never emits it


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ConfidenceKind(str, Enum):
    NOT_PROBABILISTIC = "not_probabilistic"
    UNCALIBRATED = "uncalibrated"
    CALIBRATED = "calibrated"


class Method(str, Enum):
    DETERMINISTIC = "deterministic"
    HYBRID = "hybrid"
    LLM = "llm"


class ReviewStatus(str, Enum):
    UNREVIEWED = "unreviewed"
    REVIEWED = "reviewed"
