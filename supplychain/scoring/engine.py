"""Risk scorer — maps package signals to a score and allow/warn/block verdict."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal

from supplychain.ecosystems.detector import InstallEvent, PackageSpec
from supplychain.ecosystems.metadata import PackageMetadata
from supplychain import ioc as _ioc


@dataclass
class Signal:
    id: str
    points: int
    description: str


@dataclass
class PackageVerdict:
    spec: PackageSpec
    meta: PackageMetadata
    score: int
    verdict: Literal["allow", "warn", "block"]
    signals: List[Signal] = field(default_factory=list)


class RiskScorer:
    WARN_THRESHOLD = 30
    BLOCK_THRESHOLD = 60

    def score(
        self,
        spec: PackageSpec,
        meta: PackageMetadata,
        event: InstallEvent,
    ) -> PackageVerdict:
        signals: List[Signal] = []

        def add(id: str, points: int, desc: str) -> None:
            signals.append(Signal(id=id, points=points, description=desc))

        # ── Source-based (applies regardless of registry availability) ──
        if meta.source == "git":
            add("git_source", 35, "git/GitHub dependency bypasses registry")
        elif meta.source == "tarball":
            add("tarball_source", 25, "tarball install bypasses registry")
        elif meta.source == "local":
            add("local_source", 10, "local path dependency")

        if event.custom_registry:
            add("custom_registry", 10, f"custom registry: {event.custom_registry}")

        # ── Registry-only signals (skip for non-registry sources) ────────
        if meta.source == "registry":
            if meta.age_days is not None:
                if meta.age_days < 7:
                    add("very_new_package", 25, f"published {meta.age_days}d ago")
                elif meta.age_days < 30:
                    add("new_package", 15, f"published {meta.age_days}d ago")

            if meta.maintainer_count is None:
                add("no_maintainer_data", 8, "maintainer data unavailable")
            elif meta.maintainer_count == 1:
                add("single_maintainer", 10, "single maintainer")

            if meta.has_install_script:
                add("has_install_script", 20, "has postinstall/preinstall script")

        # ── IOC: known compromised packages (mini-shai-hulud and future attacks) ──
        ioc_match = _ioc.check_package(spec.name, meta.version)
        if ioc_match:
            points = 100 if ioc_match.force_block else 40
            add(f"ioc_{ioc_match.ioc_id}", points, ioc_match.description)

        # ── IOC: install script content analysis ─────────────────────────────
        if meta.install_script_content:
            for description, severity in _ioc.check_script(meta.install_script_content):
                script_points = 100 if severity == "CRITICAL" else 50
                add("ioc_script_pattern", script_points, description)

        total = min(100, sum(s.points for s in signals))

        # Force block if any IOC signal is present, regardless of threshold
        has_ioc = any(s.id.startswith("ioc_") for s in signals)
        if has_ioc or total >= self.BLOCK_THRESHOLD:
            verdict: Literal["allow", "warn", "block"] = "block"
        elif total >= self.WARN_THRESHOLD:
            verdict = "warn"
        else:
            verdict = "allow"

        return PackageVerdict(
            spec=spec, meta=meta, score=total, verdict=verdict, signals=signals
        )
