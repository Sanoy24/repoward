"""Command line interface."""

import argparse
import getpass
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from repoward.approvals.store import Approval, ApprovalStore, ApprovalStoreError
from repoward.audit import (
    DEFAULT_KEY_ENV,
    AuditKeyError,
    AuditLog,
    AuditWriteError,
    VerifyReport,
    load_hmac_key,
    verify_log,
    write_checkpoint,
)
from repoward.policy.loader import PolicyError, load_policy
from repoward.sanitize import display_safe
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
    try:
        run_stdio(compiled, args.audit, args.approvals, key)
    except ApprovalStoreError as exc:
        _error(str(exc))
        return 1
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


def _when(timestamp: float | None) -> str:
    if timestamp is None:
        return "-"
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _print_approval(approval: Approval) -> None:
    """Print verified fields first. Everything is cleaned, so text cannot spoof the terminal."""
    print(f"Request:    {display_safe(approval.id)}")
    print(f"Status:     {display_safe(approval.status)}")
    print(f"Tool:       {display_safe(approval.tool)}")
    print(f"Repository: {display_safe(approval.repo or '-')}")
    print(f"Requested:  {display_safe(approval.principal)} at {_when(approval.ts)}")
    print(f"Expires:    {_when(approval.expires_at)}")
    print(f"Arguments:  {display_safe(approval.args_redacted)}")
    if approval.decided_by:
        print(f"Decided:    {display_safe(approval.decided_by)} at {_when(approval.decided_at)}")
    if approval.context:
        print("From GitHub (untrusted, may be written by anyone):")
        for line in display_safe(approval.context).splitlines():
            print(f"  | {line}")


def _approvals_list(args: argparse.Namespace) -> int:
    items = ApprovalStore(args.db).list(include_all=args.all)
    if not items:
        print("No requests.")
    for item in items:
        print(
            f"{display_safe(item.id)}  {display_safe(item.status)}  {display_safe(item.tool)}  "
            f"{display_safe(item.repo or '-')}  expires {_when(item.expires_at)}"
        )
    return 0


def _approvals_show(args: argparse.Namespace) -> int:
    approval = ApprovalStore(args.db).get(args.id)
    if approval is None:
        _error("no such request")
        return 1
    _print_approval(approval)
    return 0


def _decide(args: argparse.Namespace, approved: bool) -> int:
    """Audit first: if the decision cannot be recorded, it is not made."""
    store = ApprovalStore(args.db)
    approval = store.get(args.id)
    if approval is None:
        _error("no such request")
        return 1
    if approval.status != "pending":
        _error(f"this request is {display_safe(approval.status)}, not pending")
        return 1
    decided_by = getpass.getuser()
    try:
        audit = AuditLog(args.audit, load_hmac_key(DEFAULT_KEY_ENV))
        audit.append(
            {
                "event": "approval_decision",
                "approval_id": approval.id,
                "decision": "approved" if approved else "denied",
                "decided_by": decided_by,
                "principal": approval.principal,
                "tool": approval.tool,
                "repo": approval.repo,
                "args_hash": approval.args_hash,
            }
        )
    except (AuditWriteError, AuditKeyError) as exc:
        _error(f"not decided, because the decision could not be audited: {exc}")
        return 1
    if not store.decide(approval.id, approved, decided_by):
        _error("the request changed before it could be decided")
        return 1
    _print_approval(store.get(approval.id) or approval)
    return 0


def _approvals_approve(args: argparse.Namespace) -> int:
    return _decide(args, approved=True)


def _approvals_deny(args: argparse.Namespace) -> int:
    return _decide(args, approved=False)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repoward", description=__doc__)
    parser.add_argument("--version", action="version", version=version("repoward"))
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="serve MCP over stdio")
    serve.add_argument("--policy", type=Path, required=True, help="policy YAML file")
    serve.add_argument("--audit", type=Path, required=True, help="audit JSONL file")
    serve.add_argument("--approvals", type=Path, required=True, help="approvals database")
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

    approvals = commands.add_parser("approvals", help="review requests waiting for a human")
    approvals.add_argument("--db", type=Path, required=True, help="approvals database")
    approval_commands = approvals.add_subparsers(dest="approvals_command", required=True)

    listing = approval_commands.add_parser("list", help="show pending requests")
    listing.add_argument("--all", action="store_true", help="include decided requests")
    listing.set_defaults(run=_approvals_list)

    show = approval_commands.add_parser("show", help="show one request in full")
    show.add_argument("id")
    show.set_defaults(run=_approvals_show)

    for name, handler in (("approve", _approvals_approve), ("deny", _approvals_deny)):
        decision = approval_commands.add_parser(name, help=f"{name} a request")
        decision.add_argument("id")
        decision.add_argument("--audit", type=Path, required=True, help="audit JSONL file")
        decision.set_defaults(run=handler)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface and return an exit code."""
    args = _build_parser().parse_args(argv)
    try:
        return int(args.run(args))
    except ApprovalStoreError as exc:
        _error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
