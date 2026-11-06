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
