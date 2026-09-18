#!/usr/bin/env python3
"""Convenience entry point so the tool can be run as `python cli.py ...`
straight from a repo clone, without installing the package.

Equivalent to the installed `bola-scan` command. See
bola_framework/cli.py for the full flag reference, or run:

    python cli.py scan --help
"""

import sys

from bola_framework.cli import main

if __name__ == "__main__":
    sys.exit(main())
