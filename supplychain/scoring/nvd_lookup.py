"""Lightweight NVD CVE lookup for supply chain scoring."""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE: Dict[str, tuple] = {}  # key -> (expire_time, result)
_CACHE_TTL = 300  # 5 minutes


def _cache_get(key: str) -> Optional[List[Dict[str, Any]]]:
    if key in _CACHE:
        expire, result = _CACHE[key]
        if time.monotonic() < expire:
            return result
        del _CACHE[key]
    return None


def _cache_set(key: str, result: List[Dict[str, Any]]) -> None:
    _CACHE[key] = (time.monotonic() + _CACHE_TTL, result)


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    return "low"


def fetch_cves(package_name: str, ecosystem: str) -> List[Dict[str, Any]]:
    """Query NVD for CVEs matching package_name.

    Returns list of {id, severity, cvss_score, title} dicts.
    Fails open: returns [] on network error, rate limit, or timeout.
    """
    cache_key = f"{ecosystem}:{package_name}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    params = urllib.parse.urlencode({
        "keywordSearch": package_name,
        "resultsPerPage": "10",
    })
    url = f"{NVD_API_URL}?{params}"

    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
    except Exception:
        _cache_set(cache_key, [])
        return []

    results: List[Dict[str, Any]] = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        # Get CVSS score (v3.1 > v3.0 > v2)
        metrics = cve.get("metrics", {})
        cvss_score: Optional[float] = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                data_item = metrics[key][0].get("cvssData", {})
                cvss_score = data_item.get("baseScore")
                if cvss_score is not None:
                    break

        if cvss_score is None:
            continue

        # Filter: only include if package name appears in CPE product
        affected = cve.get("configurations", [])
        cpe_strings = []
        for config in affected:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe_strings.append(match.get("criteria", ""))

        # Post-filter by CPE product name to reduce false positives.
        # CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
        # Match against the product field (index 4) to avoid substring hits
        # like "express" matching "outlook_express" or "internet_explorer".
        pkg_lower = package_name.lower().lstrip("@").replace("/", "_").replace("-", "_")
        pkg_raw = package_name.lower()
        if cpe_strings:
            matched = False
            for cpe in cpe_strings:
                parts = cpe.lower().split(":")
                # CPE 2.3: parts[4] = product
                product = parts[4] if len(parts) > 4 else ""
                if product == pkg_lower or product == pkg_raw.replace("/", "_").replace("-", "_"):
                    matched = True
                    break
                # Fallback: scoped packages like @scope/name — check vendor:product pair
                if len(parts) > 5 and "/" in package_name.lower():
                    scope, name = package_name.lower().lstrip("@").split("/", 1)
                    if parts[3] == scope and parts[4] == name:
                        matched = True
                        break
            if not matched:
                continue

        # Description
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        if len(desc) > 80:
            title = f"{cve_id}: {desc[:80]}..."
        else:
            title = f"{cve_id}: {desc}" if desc else cve_id

        results.append({
            "id": cve_id,
            "severity": _cvss_to_severity(cvss_score),
            "cvss_score": cvss_score,
            "title": title,
        })

    _cache_set(cache_key, results)
    return results
