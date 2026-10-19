"""Enable ``python -m malscore`` as an alias for the ``malscore`` command."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
