"""Every tool name this project defines, with its risk class.

Policy files are validated against this catalog, including tools not implemented yet.
"""

from enum import StrEnum


class RiskClass(StrEnum):
    READ = "read"
    WRITE = "write"
    DANGEROUS = "dangerous"


TOOL_CATALOG: dict[str, RiskClass] = {
    "ping": RiskClass.READ,
    "github_list_issues": RiskClass.READ,
    "github_get_issue": RiskClass.READ,
    "github_search_code": RiskClass.READ,
    "github_get_file": RiskClass.READ,
    "ci_get_status": RiskClass.READ,
    "ci_get_job_logs": RiskClass.READ,
    "github_create_branch": RiskClass.WRITE,
    "github_commit_files": RiskClass.WRITE,
    "github_create_pull_request": RiskClass.WRITE,
    "github_comment": RiskClass.WRITE,
    "github_merge_pull_request": RiskClass.DANGEROUS,
    "github_delete_branch": RiskClass.DANGEROUS,
}

# Read tools that can return text written by other people, which sets the untrusted_input label.
UNTRUSTED_TEXT_TOOLS = frozenset(
    {"github_list_issues", "github_get_issue", "ci_get_status", "ci_get_job_logs"}
)

# Receipts get their own token, so no tool's token ever needs this permission.
RECEIPT_PERMISSIONS = {"statuses": "write"}

_ISSUES_READ = {"issues": "read", "pull_requests": "read"}
_ISSUES_WRITE = {"issues": "write", "pull_requests": "write"}
_CONTENTS_READ = {"contents": "read"}
_CONTENTS_WRITE = {"contents": "write"}

# The GitHub permissions each tool needs, used to limit its token when running as a GitHub App.
TOOL_PERMISSIONS: dict[str, dict[str, str]] = {
    "ping": {},
    "github_list_issues": _ISSUES_READ,
    "github_get_issue": _ISSUES_READ,
    "github_search_code": _CONTENTS_READ,
    "github_get_file": _CONTENTS_READ,
    "ci_get_status": {"actions": "read", "statuses": "read"},
    "ci_get_job_logs": {"actions": "read"},
    "github_create_branch": _CONTENTS_WRITE,
    "github_commit_files": _CONTENTS_WRITE,
    "github_create_pull_request": {"contents": "read", "pull_requests": "write"},
    "github_comment": _ISSUES_WRITE,
    "github_merge_pull_request": {"contents": "write", "pull_requests": "read"},
    "github_delete_branch": _CONTENTS_WRITE,
}
