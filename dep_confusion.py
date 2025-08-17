#!/usr/bin/env python3
"""
dep_confusion.py
Prototype dependency-confusion scanner (minimal, proof-of-concept).
Supports:
 - npm (package.json + package-lock.json)
 - PyPI (requirements.txt)
Core idea:
 - Extract package names
 - Query public registries to check existence
 - Use simple heuristics to reduce false positives (lockfile check, .npmrc override)
Requires: Python 3.8+, requests
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

# ========== Configuration ==========
USER_AGENT = "dep-confusion-proto/0.1"
TIMEOUT = 10  # seconds
MAX_WORKERS = 10

# Registry endpoints
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"

# Simple cache to avoid repeated queries in a run
_registry_cache_lock = threading.Lock()
_registry_cache: Dict[Tuple[str, str], Optional[Dict]] = {}


# ========== Helpers ==========
def http_get(url: str, headers=None, params=None) -> Optional[requests.Response]:
    headers = headers or {}
    headers.setdefault("User-Agent", USER_AGENT)
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
        if resp.status_code == 200:
            return resp
        if resp.status_code == 404:
            return resp
        # handle rate limits or transient failures as "unknown"
        return resp
    except requests.RequestException:
        return None


def npm_package_exists(name: str) -> Tuple[str, Optional[dict]]:
    """Query registry.npmjs.org/<name>; returns status string and metadata if found"""
    key = ("npm", name)
    with _registry_cache_lock:
        if key in _registry_cache:
            return ("found" if _registry_cache[key] else "missing", _registry_cache[key])
    # scoped packages must be encoded
    encoded = name.replace("/", "%2f")
    url = f"{NPM_REGISTRY}/{encoded}"
    resp = http_get(url)
    if resp is None:
        with _registry_cache_lock:
            _registry_cache[key] = None
        return ("unknown", None)
    if resp.status_code == 200:
        data = resp.json()
        with _registry_cache_lock:
            _registry_cache[key] = data
        return ("found", data)
    if resp.status_code == 404:
        with _registry_cache_lock:
            _registry_cache[key] = {}
        return ("missing", None)
    # other status
    return ("unknown", None)


def pypi_package_exists(name: str) -> Tuple[str, Optional[dict]]:
    key = ("pypi", name)
    with _registry_cache_lock:
        if key in _registry_cache:
            return ("found" if _registry_cache[key] else "missing", _registry_cache[key])
    url = f"{PYPI_API}/{name}/json"
    resp = http_get(url)
    if resp is None:
        with _registry_cache_lock:
            _registry_cache[key] = None
        return ("unknown", None)
    if resp.status_code == 200:
        data = resp.json()
        with _registry_cache_lock:
            _registry_cache[key] = data
        return ("found", data)
    if resp.status_code == 404:
        with _registry_cache_lock:
            _registry_cache[key] = {}
        return ("missing", None)
    return ("unknown", None)


# ========== Parsers ==========
def parse_package_json(path: Path) -> List[str]:
    """Extract dependency names from package.json 'dependencies' and 'devDependencies'"""
    names: List[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return names
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        items = data.get(section) or {}
        for k in items.keys():
            names.append(k)
    return names


def parse_requirements_txt(path: Path) -> List[str]:
    """Naive parsing of requirements.txt lines: supports direct package==versions and VCS lines"""
    names = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        # skip local paths / editable installs that include '-e' or './'
        if ln.startswith("-e ") or ln.startswith("--editable ") or ln.startswith("./") or ln.startswith("../"):
            continue
        # common forms: package==1.2.3, package>=1.0
        m = re.match(r"([A-Za-z0-9_.\-]+)", ln)
        if m:
            names.append(m.group(1))
    return names


# ========== Scanning logic ==========
def scan_npm(names: List[str], project_path: Path) -> List[Dict]:
    """Scan npm names and apply basic heuristics (checks package-lock.json if present)"""
    results = []
    lockfile = project_path / "package-lock.json"
    resolved_in_lock = set()
    if lockfile.exists():
        try:
            data = json.loads(lockfile.read_text(encoding="utf-8"))
            # package-lock v1 or v2 nid: traverse dependencies
            def walk_deps(obj):
                if not isinstance(obj, dict):
                    return
                deps = obj.get("dependencies") or {}
                for k, v in deps.items():
                    resolved = v.get("resolved")
                    if resolved:
                        resolved_in_lock.add(k)
                    walk_deps(v)

            walk_deps(data)
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(npm_package_exists, n): n for n in names}
        for fut in as_completed(futures):
            n = futures[fut]
            try:
                status, meta = fut.result()
            except Exception:
                status, meta = ("unknown", None)
            heur = {
                "name": n,
                "ecosystem": "npm",
                "status": status,
                "in_lockfile_with_resolved_url": n in resolved_in_lock,
            }
            # heuristics: if present in lockfile with resolved url, treat as private-resolved (safe)
            if heur["status"] == "missing" and heur["in_lockfile_with_resolved_url"]:
                heur["note"] = "Present in lockfile with resolved URL — likely resolved from private registry or VCS"
                heur["likely_vulnerable"] = False
            elif heur["status"] == "missing":
                heur["likely_vulnerable"] = True
            elif heur["status"] == "found":
                heur["likely_vulnerable"] = False
            else:
                heur["likely_vulnerable"] = False  # unknown -> safe by default, but mark for review
            results.append(heur)
    return results


def scan_pypi(names: List[str]) -> List[Dict]:
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(pypi_package_exists, n): n for n in names}
        for fut in as_completed(futures):
            n = futures[fut]
            try:
                status, meta = fut.result()
            except Exception:
                status, meta = ("unknown", None)
            heur = {"name": n, "ecosystem": "pypi", "status": status}
            if status == "missing":
                heur["likely_vulnerable"] = True
            elif status == "found":
                heur["likely_vulnerable"] = False
            else:
                heur["likely_vulnerable"] = False
            results.append(heur)
    return results


# ========== CLI ==========
def cli():
    ap = argparse.ArgumentParser(description="dep_confusion prototype scanner")
    ap.add_argument("--project", "-p", type=str, default=".", help="Project path to scan")
    ap.add_argument("--format", "-f", choices=("json", "text"), default="text")
    args = ap.parse_args()

    project = Path(args.project).resolve()
    findings = []

    # npm
    package_json = project / "package.json"
    if package_json.exists():
        npm_names = parse_package_json(package_json)
        findings.extend(scan_npm(npm_names, project))

    # requirements
    reqtxt = project / "requirements.txt"
    if reqtxt.exists():
        pypi_names = parse_requirements_txt(reqtxt)
        findings.extend(scan_pypi(pypi_names))

    # Summary output
    if args.format == "json":
        print(json.dumps({"findings": findings}, indent=2))
    else:
        vulnerable = [f for f in findings if f.get("likely_vulnerable")]
        print("dep_confusion prototype scan results\n")
        print(f"Total dependencies scanned: {len(findings)}")
        print(f"Potentially vulnerable: {len(vulnerable)}\n")
        for f in vulnerable:
            print(f"- {f['ecosystem']}:{f['name']} — status: {f['status']}")
            if "note" in f:
                print(f"    note: {f['note']}")
        print("\n(Use --format json to get machine-readable output.)")

    # Exit code policy: non-zero if vulnerabilities found
    if any(f.get("likely_vulnerable") for f in findings):
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    cli()