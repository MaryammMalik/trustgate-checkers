# TrustGate

TrustGate is an automated code review pipeline that checks AI-generated pull requests for two categories of risk before they are merged.

## Checkers

### Dependency Verifier
Scans all Python imports in a target branch and verifies each third-party package exists on PyPI. Flags any import not found as a possible hallucinated dependency - a known AI-coding risk.

Key features:
- Uses sys.stdlib_module_names (Python 3.10+) for a complete stdlib filter
- IMPORT_TO_PYPI mapping handles packages where import name differs from PyPI name (e.g. cv2 -> opencv-python, sklearn -> scikit-learn)
- ALLOWLIST for private/internal packages that won't appear on PyPI
- Detects local packages within the scanned repo to avoid false positives
- Cross-checks imports against requirements.txt and flags undeclared dependencies
- Handles PyPI rate limiting (429) conservatively

### License Checker
Scans the first 15 lines of every .py file for license headers incompatible with an MIT-licensed project. Covers GPL, LGPL, AGPL, EUPL, Apache, MPL, BUSL, SSPL, Elastic License, Commons Clause, and proprietary notices.

Key features:
- Word-boundary regex for short patterns (AGPL, LGPL, BUSL, ELv2) to avoid substring collisions
- Negation context detection: "this is NOT GPL" is escalated to Bob, not auto-reported
- Two-tier system: confident matches are reported directly; ambiguous matches are escalated to Bob
- Bob / OpenAI-compatible LLM escalation for borderline cases

## Project Structure

    TrustGate/
    backend/
        checkers/
            dependency_verifier.py
            license_checker.py
    tests/
        fixtures/
            clean_branch_a/
            clean_branch_b/
            clean_branch_c/
            dirty_gpl_header/
            dirty_hallucinated_dep/
        test_checkers.py
    screenshots/
    runs/
    requirements.txt
    .gitignore
    README.md

## Setup

    pip install -r requirements.txt

For Bob escalation in the License Checker, set your API key:

    $env:OPENAI_API_KEY = "sk-..."

## Running Tests

    pytest tests/ -v

## Running Checkers Manually

    python -m backend.checkers.dependency_verifier
    python -m backend.checkers.license_checker

## Output Format

Each checker writes a JSON file to runs/<run_id>.json:

    {
      "run_id": "...",
      "agent": "dependency_verifier",
      "member": "maryam-malik",
      "pr": "path/to/branch",
      "findings": [
        {
          "file": "...",
          "line": 0,
          "severity": "high | medium | low",
          "evidence": "...",
          "confidence": 0.8
        }
      ],
      "status": "success"
    }

## Customisation

### Adding private/internal packages (Dependency Verifier)
Edit ALLOWLIST in dependency_verifier.py:

    ALLOWLIST = {"mycompany_sdk", "internal_auth"}

### Adding import-to-PyPI name mappings
Edit IMPORT_TO_PYPI in dependency_verifier.py:

    IMPORT_TO_PYPI = {"myimport": "my-pypi-package-name"}

### Overriding the Bob escalation endpoint (License Checker)
Set environment variables before running:

    $env:BOB_API_URL = "https://your-endpoint/v1/chat/completions"
    $env:BOB_MODEL   = "gpt-4o"



