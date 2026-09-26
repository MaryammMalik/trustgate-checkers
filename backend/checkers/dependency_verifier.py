"""
Dependency Verifier - TrustGate checker
Owner: Maryam Malik

Scans a target repo for third-party Python imports and verifies each one
actually exists on PyPI. Flags imports that don't exist as possible
hallucinated dependencies (a known AI-coding risk).
"""

import re
import sys
import json
import time
import pathlib
import requests

# ---------------------------------------------------------------------------
# Known-safe sets — nothing in these sets is ever sent to PyPI
# ---------------------------------------------------------------------------

# Full standard library for the running Python version (Python 3.10+).
# Falls back to a manual set for older versions.
if hasattr(sys, "stdlib_module_names"):
    STDLIB = sys.stdlib_module_names
else:
    STDLIB = {
        "os", "sys", "re", "json", "math", "time", "typing", "pathlib",
        "itertools", "functools", "collections", "datetime", "random",
        "subprocess", "logging", "unittest", "abc", "io", "csv", "glob",
        "shutil", "socket", "threading", "asyncio", "enum", "dataclasses",
        "string", "copy", "hashlib", "base64", "uuid", "argparse", "traceback",
        "struct", "array", "queue", "heapq", "bisect", "weakref", "contextlib",
        "warnings", "inspect", "ast", "importlib", "pkgutil", "textwrap",
        "html", "http", "urllib", "email", "xml", "sqlite3", "zipfile",
        "tarfile", "tempfile", "stat", "fnmatch", "difflib", "pprint",
        "configparser", "secrets", "ssl", "ftplib", "builtins",
    }

# Platform-specific stdlib modules that exist only on Windows or Unix.
# Not present in sys.stdlib_module_names on the other platform.
PLATFORM_STDLIB = {
    # Windows-only
    "winreg", "winsound", "msvcrt", "nt",
    # Unix-only
    "fcntl", "termios", "pty", "grp", "pwd", "posix", "resource",
}

# Private or internal packages that will never appear on public PyPI.
# Add your team's internal package names here to suppress false positives.
ALLOWLIST: set = {
    # e.g. "mycompany_sdk", "internal_auth", "trustgate_core"
}

# Mapping from import name to the actual PyPI package name when they differ.
# Without this, packages like opencv-python (imported as cv2) would be
# wrongly flagged as hallucinated.
IMPORT_TO_PYPI: dict = {
    "cv2":          "opencv-python",
    "sklearn":      "scikit-learn",
    "PIL":          "Pillow",
    "bs4":          "beautifulsoup4",
    "dotenv":       "python-dotenv",
    "yaml":         "PyYAML",
    "Crypto":       "pycryptodome",
    "attr":         "attrs",
    "dateutil":     "python-dateutil",
    "gi":           "PyGObject",
    "wx":           "wxPython",
    "usb":          "pyusb",
    "serial":       "pyserial",
    "gtk":          "PyGTK",
    "OpenSSL":      "pyOpenSSL",
    "pkg_resources":"setuptools",
    "google.cloud": "google-cloud",
    "jwt":          "PyJWT",
    "magic":        "python-magic",
    "Image":        "Pillow",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def imports_from(path):
    """Walk all .py files under `path` and collect top-level import names.

    Skips dunder/private names (starting with '_') which are never real
    third-party packages.
    """
    names = set()
    for p in pathlib.Path(path).rglob("*.py"):
        try:
            lines = p.read_text(errors="ignore").splitlines()
        except Exception:
            continue
        for line in lines:
            match = re.match(r"\s*(?:from|import)\s+([a-zA-Z0-9_]+)", line)
            if match:
                name = match.group(1)
                # Skip dunder and private names (__future__, _thread, etc.)
                if not name.startswith("_"):
                    names.add(name)
    return names


def is_local_package(name, pr_branch_path):
    """Return True if `name` is a local module/package inside the PR branch.

    Prevents false positives when the repo being scanned has its own
    internal modules (e.g. a `utils/` folder or a `helpers.py` file).
    """
    root = pathlib.Path(pr_branch_path)
    return (root / name).is_dir() or (root / f"{name}.py").exists()


def exists_on_pypi(name):
    """Return True if `name` is a real package on PyPI.

    Handles network errors and rate limiting conservatively:
    when in doubt, don't flag (avoid false positives).
    """
    # Translate import name → PyPI package name where they differ
    pypi_name = IMPORT_TO_PYPI.get(name, name)
    try:
        r = requests.get(
            f"https://pypi.org/pypi/{pypi_name}/json", timeout=8
        )
        if r.status_code == 429:
            # Rate limited — skip conservatively rather than wrongly flagging
            return True
        return r.status_code == 200
    except requests.RequestException:
        # PyPI unreachable — skip conservatively
        return True


def parse_requirements(pr_branch_path):
    """Return the set of package names declared in requirements.txt (if any).

    Names are normalised to lowercase with hyphens replaced by underscores
    so they can be compared against import names.
    """
    req_file = pathlib.Path(pr_branch_path) / "requirements.txt"
    if not req_file.exists():
        return set()
    names = set()
    for line in req_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip version specifiers: requests>=2.0 → requests
        pkg = re.split(r"[>=<!;\[]", line)[0].strip()
        if pkg:
            names.add(pkg.lower().replace("-", "_"))
    return names


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run(pr_branch_path, run_id, member="maryam-malik"):
    """
    Main entry point called by the orchestrator.

    Args:
        pr_branch_path: path to the branch/repo folder to scan
        run_id: unique id for this run (used as the output filename)
        member: who owns this checker (default: maryam-malik)

    Returns:
        dict matching the shared runs/ JSON contract. Also writes the
        result to runs/<run_id>.json.
    """
    findings = []
    all_imports = imports_from(pr_branch_path)
    declared_reqs = parse_requirements(pr_branch_path)

    # Remove stdlib, platform-stdlib, allowlisted, and local packages
    third_party = sorted(
        name for name in all_imports
        if name not in STDLIB
        and name not in PLATFORM_STDLIB
        and name not in ALLOWLIST
        and not is_local_package(name, pr_branch_path)
    )

    for name in third_party:
        pypi_exists = exists_on_pypi(name)
        normalised = name.lower().replace("-", "_")
        in_requirements = normalised in declared_reqs

        if not pypi_exists:
            findings.append({
                "file": "requirements/imports",
                "line": 0,
                "severity": "high",
                "evidence": (
                    f"Package '{name}' not found on PyPI: "
                    "possible hallucinated dependency"
                ),
                "confidence": 0.8,
            })
        elif not in_requirements and declared_reqs:
            # Package exists on PyPI but is missing from requirements.txt —
            # a softer warning: real package but undeclared dependency.
            findings.append({
                "file": "requirements.txt",
                "line": 0,
                "severity": "low",
                "evidence": (
                    f"Package '{name}' is imported but not listed in "
                    "requirements.txt"
                ),
                "confidence": 0.6,
            })
        time.sleep(0.1)  # be polite to PyPI's API

    result = {
        "run_id": run_id,
        "agent": "dependency_verifier",
        "member": member,
        "pr": str(pr_branch_path),
        "findings": findings,
        "status": "success",
    }

    output_path = pathlib.Path("runs") / f"{run_id}.json"
    output_path.parent.mkdir(exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    return result


if __name__ == "__main__":
    # Quick manual test: scan the current folder itself
    output = run(".", "test_run_001")
    print(json.dumps(output, indent=2))
