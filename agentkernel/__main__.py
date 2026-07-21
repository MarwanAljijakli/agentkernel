"""Run `python -m agentkernel`."""

from __future__ import annotations

import sys

from agentkernel.cli import main

raise SystemExit(main(sys.argv[1:]))
