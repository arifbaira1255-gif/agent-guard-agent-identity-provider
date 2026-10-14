"""Happy's static security analysis layer (Step 5).

    from happy.security import SecurityAnalyzer, analyze_security

    report = analyze_security(source, filename="generated.hpy")
    if not report.ok:
        print(report.format())
"""

from .analyzer import (
    HIGH_RISK_ACTIONS,
    PAYMENT_PATTERNS,
    SECRET_SINKS,
    UNSAFE_IO_OPS,
    SecurityAnalyzer,
    SecurityFinding,
    SecurityReport,
    Severity,
    analyze_security,
)

__all__ = [
    "SecurityAnalyzer",
    "SecurityReport",
    "SecurityFinding",
    "Severity",
    "analyze_security",
    "SECRET_SINKS",
    "PAYMENT_PATTERNS",
    "UNSAFE_IO_OPS",
    "HIGH_RISK_ACTIONS",
]
