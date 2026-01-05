from enum import Enum

class ScopeType(str, Enum):
    GLOBAL = "GLOBAL"
    VIRTUAL_HOST = "VIRTUAL_HOST"
    DIRECTORY = "DIRECTORY"
    LOCATION = "LOCATION"
    HTACCESS = "HTACCESS"

class FindingType(str, Enum):
    MISCONFIGURATION = "MISCONFIGURATION"
    RISKY_DEFAULT = "RISKY_DEFAULT"
    EXPOSURE = "EXPOSURE"
    INHERITANCE_CONFLICT = "INHERITANCE_CONFLICT"

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

def severity_max(a: Severity, b: Severity) -> Severity:
    order = [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL
    ]
    return order[max(order.index(a), order.index(b))]
