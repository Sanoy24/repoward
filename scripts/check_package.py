"""Fail if a built package holds anything other than the files meant to be released."""

import sys
import tarfile
import zipfile
from pathlib import Path

WHEEL_PREFIXES = ("repoward/",)
SDIST_FILES = {
    ".gitignore",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "PKG-INFO",
    "README.md",
    "SECURITY.md",
    "docs/THREAT_MODEL.md",
    "policy.example.yaml",
    "pyproject.toml",
}


def unexpected_in_wheel(names: list[str]) -> list[str]:
    return [
        name for name in names if not name.startswith(WHEEL_PREFIXES) and ".dist-info/" not in name
    ]


def unexpected_in_sdist(names: list[str]) -> list[str]:
    bad = []
    for name in names:
        _, _, inner = name.partition("/")
        allowed = (
            not inner
            or inner in SDIST_FILES
            or inner in {"src", "docs"}
            or inner.startswith("src/repoward/")
        )
        if not allowed:
            bad.append(name)
    return bad


def main(dist: Path) -> int:
    wheels = list(dist.glob("*.whl"))
    sdists = list(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        print("Expected exactly one wheel and one sdist.")
        return 1
    with zipfile.ZipFile(wheels[0]) as wheel:
        bad = unexpected_in_wheel(wheel.namelist())
    with tarfile.open(sdists[0]) as sdist:
        bad += unexpected_in_sdist(sdist.getnames())
    for name in bad:
        print(f"Unexpected file: {name}")
    if not bad:
        print("Package contents are as expected.")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "dist")))
