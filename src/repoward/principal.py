"""Who is calling. The pipeline only ever sees this object, never the transport."""

import getpass
from collections.abc import Sequence
from dataclasses import dataclass

from repoward.policy.models import IdentityMap

NO_ROLE = "identity.no_role"
AMBIGUOUS_ROLE = "identity.ambiguous_role"


@dataclass(frozen=True)
class Principal:
    id: str
    role: str
    groups: tuple[str, ...] | None = None  # From the token in HTTP mode, kept for the audit log.
    identity_problem: str | None = None  # The rule that refuses this caller, if any.


def local_principal(role: str) -> Principal:
    """The single identity of a stdio server: the OS user that launched it."""
    return Principal(id=f"local:{getpass.getuser()}", role=role)


def resolve_role(identity_map: IdentityMap | None, groups: Sequence[str]) -> tuple[str, str | None]:
    """A caller's one role, or the rule refusing them. Roles are never combined."""
    mapping = identity_map.mapping if identity_map is not None else {}
    roles = {mapping[group] for group in groups if group in mapping}
    if not roles:
        return "", NO_ROLE
    if len(roles) > 1:
        return "", AMBIGUOUS_ROLE
    return roles.pop(), None
