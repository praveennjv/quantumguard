#!/usr/bin/env python3
"""Dev helper: scan the vulnerable corpus."""
import sys
from scanner.cli.main import main

if __name__ == "__main__":
    sys.exit(main(["scan", "tests/vulnerable", "--fail-on", "never", "--format", "json"]))
