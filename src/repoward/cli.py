"""Command line interface."""

import argparse
import sys
from collections.abc import Sequence
from importlib.metadata import version
from pathlib import Path

from repoward.audit import (
    DEFAULT_KEY_ENV,
    AuditKeyError,
    VerifyReport,
    load_hmac_key,
    verify_log,
    write_checkpoint,
)
from repoward.policy.loader import PolicyError, load_policy
from repoward.server import run_stdio


def _error(message: str) -> None:
    print(f"repoward: {message}", file=sys.stderr)


def _print_policy_error(path: Path, exc: PolicyError) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        lines = []
    for issue in exc.issues:
        where = f"{path}:{issue.line}:{issue.column}" if issue.line else str(path)
        print(f"{where}: {issue.message}", file=sys.stderr)
        if issue.line and issue.line <= len(lines):
            print(f"    {lines[issue.line - 1]}", file=sys.stderr)
            if issue.column:
                print(f"    {' ' * (issue.column - 1)}^", file=sys.stderr)


def _print_report(report: VerifyReport) -> int:
    for warning in report.warnings:
        print(f"warning: {warning}")
    for error in report.errors:
        print(f"error: {error}")
    if report.ok:
        print(f"OK: {report.records} records, tip {report.tip_hash}")
        return 0
    print(f"FAILED after {report.records} valid records")
    return 1


def _validate_policy(args: argparse.Namespace) -> int:
    try:
        compiled = load_policy(args.path)
    except PolicyError as exc:
        _print_policy_error(args.path, exc)
        return 1
    print(f"OK: {len(compiled.roles)} roles, sha256 {compiled.sha256}")
    return 0


def _serve(args: argparse.Namespace) -> int:
    try:
        compiled = load_policy(args.policy)
        key = load_hmac_key(DEFAULT_KEY_ENV)
    except PolicyError as exc:
        _print_policy_error(args.policy, exc)
        return 1
    except AuditKeyError as exc:
        _error(str(exc))
        return 1
    run_stdio(compiled, args.audit, key)
    return 0


def _audit_key(args: argparse.Namespace) -> bytes | None:
    return load_hmac_key(args.key_env) if args.key_env else None


def _audit_verify(args: argparse.Namespace) -> int:
    try:
        return _print_report(verify_log(args.file, _audit_key(args), args.anchor))
    except AuditKeyError as exc:
        _error(str(exc))
        return 1


def _audit_checkpoint(args: argparse.Namespace) -> int:
    try:
        return _print_report(write_checkpoint(args.file, args.out, _audit_key(args)))
    except AuditKeyError as exc:
        _error(str(exc))
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repoward", description=__doc__)
    parser.add_argument("--version", action="version", version=version("repoward"))
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="serve MCP over stdio")
    serve.add_argument("--policy", type=Path, required=True, help="policy YAML file")
    serve.add_argument("--audit", type=Path, required=True, help="audit JSONL file")
    serve.set_defaults(run=_serve)

    validate = commands.add_parser("validate-policy", help="check a policy file")
    validate.add_argument("path", type=Path)
    validate.set_defaults(run=_validate_policy)

    audit = commands.add_parser("audit", help="work with audit logs")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)

    verify = audit_commands.add_parser("verify", help="check a log's hash chain")
    verify.add_argument("file", type=Path)
    verify.add_argument("--anchor", type=Path, help="anchor file from audit checkpoint")
    verify.add_argument("--key-env", help="environment variable holding the HMAC key")
    verify.set_defaults(run=_audit_verify)

    checkpoint = audit_commands.add_parser("checkpoint", help="record the log's current tip")
    checkpoint.add_argument("file", type=Path)
    checkpoint.add_argument("--out", type=Path, required=True, help="anchor file to append to")
    checkpoint.add_argument("--key-env", help="environment variable holding the HMAC key")
    checkpoint.set_defaults(run=_audit_checkpoint)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface and return an exit code."""
    args = _build_parser().parse_args(argv)
    return int(args.run(args))


if __name__ == "__main__":
    raise SystemExit(main())
