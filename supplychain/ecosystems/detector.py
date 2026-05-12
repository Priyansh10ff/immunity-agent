"""Install command parser — turns argv into a structured InstallEvent.

Supports: npm, pnpm, yarn, bun, pip, pip3, uv, poetry, cargo, go
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PackageSpec:
    raw: str          # as given by user, e.g. "express", "github:user/repo"
    name: str         # normalized name without version, e.g. "express", "@scope/pkg"
    source: str       # "registry" | "git" | "tarball" | "local"


@dataclass
class InstallEvent:
    ecosystem: str            # "npm", "pip", "cargo", etc.
    argv: List[str]           # original full argv passed to immunity
    packages: List[PackageSpec]
    custom_registry: Optional[str] = None


# (binary, subcommand) -> ecosystem
_INSTALL_MAP: Dict[tuple, str] = {
    ("npm", "install"): "npm",
    ("npm", "i"): "npm",
    ("npm", "add"): "npm",
    ("pnpm", "install"): "pnpm",
    ("pnpm", "add"): "pnpm",
    ("pnpm", "i"): "pnpm",
    ("yarn", "add"): "yarn",
    ("bun", "add"): "bun",
    ("bun", "install"): "bun",
    ("pip", "install"): "pip",
    ("pip3", "install"): "pip",
    ("uv", "add"): "uv",
    ("poetry", "add"): "pip",
    ("cargo", "add"): "cargo",
    ("cargo", "install"): "cargo",
    ("go", "get"): "go",
    ("go", "install"): "go",
}

# Flags that consume the next token (so we don't mistake values for package names)
_VALUE_FLAGS = {
    "--registry", "--workspace", "-C", "--prefix", "--userconfig",
    "-r", "--requirement",
    "--target", "-t",
    "--index-url", "-i",
    "--extra-index-url",
    "--config-file",
}


def _classify_source(raw: str) -> str:
    if raw.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:")):
        return "git"
    if raw.startswith(("http://", "https://")) and re.search(r"\.(tgz|tar\.gz|zip)($|\?)", raw):
        return "tarball"
    if raw.startswith(("./", "../", "/")) or raw.startswith("file:"):
        return "local"
    return "registry"


def _normalize_name(raw: str, ecosystem: str) -> str:
    """Strip version specifier from a registry package name."""
    if ecosystem in ("npm", "pnpm", "yarn", "bun"):
        # @scope/name@version → @scope/name
        if raw.startswith("@"):
            bare = raw[1:].split("@")[0]
            return "@" + bare
        return raw.split("@")[0]
    elif ecosystem in ("pip", "uv"):
        m = re.match(r"^([A-Za-z0-9_.-]+)", raw)
        return m.group(1) if m else raw
    elif ecosystem == "cargo":
        return raw.split("@")[0]
    # go: full module path is the name
    return raw


def detect_install(argv: List[str]) -> Optional[InstallEvent]:
    """Parse argv (e.g. ['npm', 'install', 'express']) → InstallEvent or None.

    Returns None if the command is not a recognised package install.
    Returns an InstallEvent with empty packages if it's a manifest-only install
    (e.g. bare 'npm install' with no package names specified).
    """
    if len(argv) < 2:
        return None

    binary = argv[0].lower()

    # Special case: "uv pip install ..."
    if binary == "uv" and len(argv) >= 3 and argv[1] == "pip" and argv[2] == "install":
        eco = "uv"
        rest = argv[3:]
    else:
        sub = argv[1].lower()
        eco = _INSTALL_MAP.get((binary, sub))
        if eco is None:
            return None
        rest = argv[2:]

    packages: List[PackageSpec] = []
    custom_registry: Optional[str] = None
    skip_next = False

    for i, arg in enumerate(rest):
        if skip_next:
            skip_next = False
            continue

        if arg.startswith("--registry="):
            custom_registry = arg.split("=", 1)[1]
        elif arg == "--registry" and i + 1 < len(rest):
            custom_registry = rest[i + 1]
            skip_next = True
        elif arg in _VALUE_FLAGS and i + 1 < len(rest):
            skip_next = True
        elif arg.startswith("-"):
            pass  # other flag, ignore
        else:
            source = _classify_source(arg)
            name = _normalize_name(arg, eco) if source == "registry" else arg
            packages.append(PackageSpec(raw=arg, name=name, source=source))

    return InstallEvent(
        ecosystem=eco,
        argv=argv,
        packages=packages,
        custom_registry=custom_registry,
    )
