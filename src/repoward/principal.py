"""Who is calling. The pipeline only ever sees this object, never the transport."""

import getpass
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    id: str
    role: str


def local_principal(role: str) -> Principal:
    """The single identity of a stdio server: the OS user that launched it."""
    return Principal(id=f"local:{getpass.getuser()}", role=role)
