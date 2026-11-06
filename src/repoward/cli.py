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
from repoward.flow import FlowStore, FlowStoreError
from repoward.policy.loader import PolicyError, load_policy
from repoward.sanitize import display_safe
from repoward.server import run_stdio
from repoward.setup import (
    APPROVALS_FILE,
    AUDIT_FILE,
    FLOW_FILE,
    POLICY_FILE,
    STARTER_ROLES,
    client_config,
    default_dir,
    write_starter,
)


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
    path = args.path or default_dir() / POLICY_FILE
    try:
        compiled = load_policy(path)
    except PolicyError as exc:
        _print_policy_error(path, exc)
        return 1
    print(f"OK: {len(compiled.roles)} roles, sha256 {compiled.sha256}")
    return 0


def _serve(args: argparse.Namespace) -> int:
    directory = args.dir or default_dir()
    policy_path = args.policy or directory / POLICY_FILE
    if not policy_path.exists():
        _error(f"no policy at {policy_path}. Create one with: repoward init --repo owner/name")
        return 1
    try:
        compiled = load_policy(policy_path)
        key = load_hmac_key(DEFAULT_KEY_ENV)
    except PolicyError as exc:
        _print_policy_error(policy_path, exc)
        return 1
    except AuditKeyError as exc:
        _error(str(exc))
        return 1
    try:
        directory.mkdir(parents=True, exist_ok=True)
        run_stdio(
            compiled,
            args.audit or directory / AUDIT_FILE,
            args.approvals or directory / APPROVALS_FILE,
            args.flow or directory / FLOW_FILE,
            key,
        )
    except OSError as exc:
        _error(f"cannot use {directory}: {exc.strerror}")
        return 1
    except (ApprovalStoreError, FlowStoreError) as exc:
        _error(str(exc))
        return 1
    return 0


def _init(args: argparse.Namespace) -> int:
    directory = args.dir or default_dir()
    try:
        path = write_starter(directory, args.repo, args.role)
    except FileExistsError:
        _error(f"{directory / POLICY_FILE} already exists, and it was left unchanged")
        return 1
    except PolicyError as exc:
        for issue in exc.issues:
            _error(issue.message)
        return 1
    except OSError as exc:
        _error(f"cannot write to {directory}: {exc.strerror}")
        return 1
    print(f"Created {path}, with role '{args.role}'.\n")
    print("Next steps:\n")
    print("1. Create a fine-grained GitHub token limited to those repositories:")
    print("   https://github.com/settings/personal-access-tokens/new\n")
    print("2. Add this to your MCP client's config, replacing <your-token>:\n")
    print(client_config(directory))
    print(
        "\n3. Protect your default branch with a ruleset that has no bypass for the token's owner."
    )
    print("\nImportant: this is not a security boundary for an agent that has a shell running as")
    print(
        "the same OS user. It could use git directly, read the token or approve its own requests."
    )
    print("Separate them, or give the agent MCP tools only. Details:")
    print("https://github.com/Sanoy24/repoward/blob/main/docs/THREAT_MODEL.md")
    return 0


def _audit_key(args: argparse.Namespace) -> bytes | None:
    return load_hmac_key(args.key_env) if args.key_env else None


def _audit_verify(args: argparse.Namespace) -> int:
    try:
        path = args.file or default_dir() / AUDIT_FILE
        return _print_report(verify_log(path, _audit_key(args), args.anchor))
    except AuditKeyError as exc:
        _error(str(exc))
        return 1


def _audit_checkpoint(args: argparse.Namespace) -> int:
    try:
        path = args.file or default_dir() / AUDIT_FILE
        return _print_report(write_checkpoint(path, args.out, _audit_key(args)))
    except AuditKeyError as exc:
        _error(str(exc))
        return 1


def _in_home(path: Path | None, filename: str) -> Path:
    """Use the given path, or a file in the home directory, which is created if needed."""
    if path is not None:
        return path
    directory = default_dir()
    directory.mkdir(parents=True, exist_ok=True)
    return directory / filename


def _approval_store(args: argparse.Namespace) -> ApprovalStore:
    return ApprovalStore(_in_home(args.db, APPROVALS_FILE))


def _flow_store(args: argparse.Namespace) -> FlowStore:
    return FlowStore(_in_home(args.db, FLOW_FILE))


def _audit_path(args: argparse.Namespace) -> Path:
    return _in_home(args.audit, AUDIT_FILE)


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
    items = _approval_store(args).list(include_all=args.all)
    if not items:
        print("No requests.")
    for item in items:
        print(
            f"{display_safe(item.id)}  {display_safe(item.status)}  {display_safe(item.tool)}  "
            f"{display_safe(item.repo or '-')}  expires {_when(item.expires_at)}"
        )
    return 0


def _approvals_show(args: argparse.Namespace) -> int:
    approval = _approval_store(args).get(args.id)
    if approval is None:
        _error("no such request")
        return 1
    _print_approval(approval)
    return 0


def _decide(args: argparse.Namespace, approved: bool) -> int:
    """Audit first: if the decision cannot be recorded, it is not made."""
    store = _approval_store(args)
    approval = store.get(args.id)
    if approval is None:
        _error("no such request")
        return 1
    if approval.status != "pending":
        _error(f"this request is {display_safe(approval.status)}, not pending")
        return 1
    decided_by = getpass.getuser()
    try:
        audit = AuditLog(_audit_path(args), load_hmac_key(DEFAULT_KEY_ENV))
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


def _flow_status(args: argparse.Namespace) -> int:
    labels = _flow_store(args).active()
    if not labels:
        print("No active labels.")
    for label in labels:
        print(
            f"{display_safe(label.principal)}  {display_safe(label.kind)}  "
            f"{display_safe(label.source)}  expires {_when(label.expires_at)}"
        )
    return 0


def _flow_reset(args: argparse.Namespace) -> int:
    """Audit first: if the reset cannot be recorded, it does not happen."""
    store = _flow_store(args)
    try:
        AuditLog(_audit_path(args), load_hmac_key(DEFAULT_KEY_ENV)).append(
            {
                "event": "flow_reset",
                "principal": args.principal,
                "decided_by": getpass.getuser(),
            }
        )
    except (AuditWriteError, AuditKeyError) as exc:
        _error(f"not reset, because the reset could not be audited: {exc}")
        return 1
    print(f"Cleared {store.reset(args.principal)} labels.")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="repoward", description=__doc__)
    parser.add_argument("--version", action="version", version=version("repoward"))
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create a safe starter policy")
    init.add_argument(
        "--repo", action="append", required=True, help="owner/name to allow; repeatable"
    )
    init.add_argument(
        "--role", choices=STARTER_ROLES, default="reader", help="role for this server"
    )
    init.add_argument("--dir", type=Path, help="directory for repoward's files")
    init.set_defaults(run=_init)

    serve = commands.add_parser("serve", help="serve MCP over stdio")
    serve.add_argument("--dir", type=Path, help="directory for repoward's files")
    serve.add_argument("--policy", type=Path, help="policy YAML file")
    serve.add_argument("--audit", type=Path, help="audit JSONL file")
    serve.add_argument("--approvals", type=Path, help="approvals database")
    serve.add_argument("--flow", type=Path, help="flow guard database")
    serve.set_defaults(run=_serve)

    validate = commands.add_parser("validate-policy", help="check a policy file")
    validate.add_argument("path", type=Path, nargs="?")
    validate.set_defaults(run=_validate_policy)

    audit = commands.add_parser("audit", help="work with audit logs")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)

    verify = audit_commands.add_parser("verify", help="check a log's hash chain")
    verify.add_argument("file", type=Path, nargs="?")
    verify.add_argument("--anchor", type=Path, help="anchor file from audit checkpoint")
    verify.add_argument("--key-env", help="environment variable holding the HMAC key")
    verify.set_defaults(run=_audit_verify)

    checkpoint = audit_commands.add_parser("checkpoint", help="record the log's current tip")
    checkpoint.add_argument("file", type=Path, nargs="?")
    checkpoint.add_argument("--out", type=Path, required=True, help="anchor file to append to")
    checkpoint.add_argument("--key-env", help="environment variable holding the HMAC key")
    checkpoint.set_defaults(run=_audit_checkpoint)

    approvals = commands.add_parser("approvals", help="review requests waiting for a human")
    approvals.add_argument("--db", type=Path, help="approvals database")
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
        decision.add_argument("--audit", type=Path, help="audit JSONL file")
        decision.set_defaults(run=handler)

    flow = commands.add_parser(
        "flow", help="inspect or clear what agents are marked as having read"
    )
    flow.add_argument("--db", type=Path, help="flow guard database")
    flow_commands = flow.add_subparsers(dest="flow_command", required=True)

    status = flow_commands.add_parser("status", help="show active labels")
    status.set_defaults(run=_flow_status)

    reset = flow_commands.add_parser("reset", help="clear labels so writes are allowed again")
    reset.add_argument("--principal", help="only this principal (default: everyone)")
    reset.add_argument("--audit", type=Path, help="audit JSONL file")
    reset.set_defaults(run=_flow_reset)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface and return an exit code."""
    args = _build_parser().parse_args(argv)
    try:
        return int(args.run(args))
    except (ApprovalStoreError, FlowStoreError) as exc:
        _error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
