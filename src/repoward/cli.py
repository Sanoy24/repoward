"""Command line interface."""

import argparse
from collections.abc import Sequence
from importlib.metadata import version

from repoward.server import run_stdio


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface and return an exit code."""
    parser = argparse.ArgumentParser(prog="repoward", description=__doc__)
    parser.add_argument("--version", action="version", version=version("repoward"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve", help="serve MCP over stdio")

    parser.parse_args(argv)
    run_stdio()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
