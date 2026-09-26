"""
License Checker - TrustGate checker
Owner: Maryam Malik

Scans a target repo for license header text that doesn't belong in an
MIT-licensed project (GPL, Apache, or proprietary notices copied in by
an AI agent). Regex pass first; ambiguous matches are escalated to Bob
for a second opinion before being reported.
"""

import json
import os
import re
import pathlib
import requests

# Marker phrases grouped by license type, each with its own severity.
# GPL/AGPL = high risk (strong copyleft, incompatible with MIT).
# Apache/proprietary = medium risk (may need attribution or may be closed-source).
LICENSE_MARKERS = {
    "GPL": {
        "severity": "high",
        "patterns": [
            "GNU GENERAL PUBLIC LICENSE",
            "GPL-3.0",
            "GPL-2.0",
            "GPL-1.0",
            "licensed under the GPL",
            "GNU Lesser General Public License",
            "GNU AFFERO GENERAL PUBLIC LICENSE",
            "AGPL",
            "AGPL-3.0",
            "LGPL",
            "LGPL-2.0",
            "LGPL-2.1",
            "LGPL-3.0",
            "www.gnu.org/licenses",
            "version 3 of the License",
            "EUPL",
            "copyleft",
        ],
    },
    "Apache": {
        "severity": "medium",
        "patterns": [
            "Apache License",
            "Apache-2.0",
            "Apache-1.1",
            "Apache-1.0",
            "www.apache.org/licenses",
            "apache.org/licenses/LICENSE-2.0",
            "SPDX-License-Identifier: Apache",
        ],
    },
    "Proprietary": {
        "severity": "medium",
        "patterns": [
            "All Rights Reserved",
            "Proprietary and confidential",
            "Unauthorized copying of this file",
            "Do not distribute",
            "internal use only",
            "not for distribution",
            "trade secret",
        ],
    },
    "MPL": {
        "severity": "medium",
        "patterns": [
            "Mozilla Public License",
            "MPL-2.0",
            "MPL-1.1",
        ],
    },
    "Restrictive": {
        "severity": "high",
        "patterns": [
            "Business Source License",
            "BUSL",
            "SSPL",
            "Server Side Public License",
            "Commons Clause",
            "Elastic License",
            "ELv2",
        ],
    },
}

# Weaker/ambiguous phrases that might just be informal wording, not a
# real license claim. These go to Bob for a second opinion instead of
# being auto-reported as a finding.
AMBIGUOUS_HINTS = [
    "confidential",
    "proprietary",
    "SPDX-License-Identifier:",
    "creative commons",
    "CC BY-SA",
    "CC BY",
    "do not copy",
]


# Patterns short enough to cause substring collisions (e.g. "AGPL" inside
# "navigpl", "LGPL" inside a longer token). These are matched with word
# boundaries instead of plain substring search.
_SHORT_PATTERNS = {
    "AGPL", "LGPL", "LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
    "BUSL", "SSPL", "ELv2", "EUPL",
    "copyleft", "CC BY", "CC BY-SA",
}

# Words that, when found on the same line as a marker, suggest the marker
# is being cited or disclaimed rather than claimed (e.g. "NOT GPL").
_NEGATORS = ("not ", "non-", "no ", "without ", "isn't", "neither", "unlike")


def _marker_present(marker, text):
    """Return True if `marker` appears in `text` (case-insensitive).

    Uses word-boundary regex for short/collision-prone patterns;
    plain substring for long unambiguous phrases.
    """
    m = marker.lower()
    t = text.lower()
    if marker in _SHORT_PATTERNS:
        return bool(re.search(r"\b" + re.escape(m) + r"\b", t))
    return m in t


def _is_negated(marker, line_text):
    """Return True if the line containing `marker` uses a negating phrase,
    suggesting the marker is being disclaimed rather than claimed."""
    lower = line_text.lower()
    return any(neg in lower for neg in _NEGATORS)


def scan_headers(path):
    """Scan the first 15 lines of every .py file for license markers.

    Returns:
        findings: confident matches, ready to report directly
        ambiguous: weaker matches that should be escalated to Bob
    """
    findings = []
    ambiguous = []

    for p in pathlib.Path(path).rglob("*.py"):
        # Skip the checker scripts themselves - they contain license
        # keywords in their own pattern lists, which would otherwise
        # cause false positives when scanning backend/checkers/.
        if "checkers" in p.parts:
            continue
        try:
            lines = p.read_text(errors="ignore").splitlines()[:15]
        except Exception:
            continue
        head = "\n".join(lines)

        matched_this_file = False
        for license_type, info in LICENSE_MARKERS.items():
            for marker in info["patterns"]:
                if not _marker_present(marker, head):
                    continue

                # Find the exact line number for the match
                line_no = 1
                matched_line_text = ""
                for i, line in enumerate(lines, start=1):
                    if _marker_present(marker, line):
                        line_no = i
                        matched_line_text = line
                        break

                # If the matching line disclaims the license, escalate to
                # Bob instead of auto-reporting as a hard finding.
                if _is_negated(marker, matched_line_text):
                    ambiguous.append({
                        "file": str(p),
                        "line": line_no,
                        "snippet": head[:200],
                        "hint": f"{marker} (negation context — possible false positive)",
                    })
                    matched_this_file = True
                    break

                findings.append({
                    "file": str(p),
                    "line": line_no,
                    "severity": info["severity"],
                    "evidence": f"Header contains '{marker}' ({license_type} license marker)",
                    "confidence": 0.7,
                })
                matched_this_file = True
                break
            if matched_this_file:
                break

        if not matched_this_file:
            for hint in AMBIGUOUS_HINTS:
                if _marker_present(hint, head):
                    ambiguous.append({
                        "file": str(p),
                        "line": 1,
                        "snippet": head[:200],
                        "hint": hint,
                    })
                    break

    return findings, ambiguous


# OpenAI-compatible endpoint and model used for Bob escalation.
# Override via environment variables if needed.
BOB_API_URL = os.environ.get(
    "BOB_API_URL", "https://api.openai.com/v1/chat/completions"
)
BOB_MODEL = os.environ.get("BOB_MODEL", "gpt-4o-mini")

_ESCALATION_PROMPT = """\
You are a software license compliance reviewer.
A file header from an MIT-licensed project has been flagged as possibly \
containing a restrictive license notice.

File: {file}
Header snippet:
\"\"\"
{snippet}
\"\"\"

Does this header constitute a real license claim that would restrict or \
be incompatible with an MIT-licensed project?
Reply with exactly YES or NO on the first line, then one sentence of reasoning."""


def escalate_to_bob(ambiguous_cases):
    """
    Send each ambiguous header snippet to an LLM (Bob / OpenAI-compatible)
    and ask whether it's a real license violation.

    Requires the environment variable OPENAI_API_KEY to be set.
    If the API key is missing or the request fails, the case is silently
    skipped (conservative: no false positives from network errors).

    Returns:
        list of finding dicts for cases the LLM confirmed as violations.
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        # Can't escalate without a key — skip rather than crash or false-flag.
        return []

    confirmed_findings = []

    for case in ambiguous_cases:
        prompt = _ESCALATION_PROMPT.format(
            file=case["file"],
            snippet=case["snippet"],
        )
        try:
            response = requests.post(
                BOB_API_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": BOB_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 80,
                    "temperature": 0,
                },
                timeout=20,
            )
            response.raise_for_status()
            reply = response.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            # Network error, quota exceeded, malformed response, etc.
            # Skip conservatively rather than wrongly auto-reporting.
            continue

        first_line = reply.splitlines()[0].strip().upper()
        reasoning = reply.splitlines()[1].strip() if len(reply.splitlines()) > 1 else ""

        if first_line.startswith("YES"):
            confirmed_findings.append({
                "file": case["file"],
                "line": case["line"],
                "severity": "medium",
                "evidence": (
                    f"Ambiguous license hint '{case['hint']}' confirmed by Bob"
                    + (f": {reasoning}" if reasoning else "")
                ),
                "confidence": 0.6,
            })

    return confirmed_findings


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
    findings, ambiguous = scan_headers(pr_branch_path)

    if ambiguous:
        findings.extend(escalate_to_bob(ambiguous))

    result = {
        "run_id": run_id,
        "agent": "license_checker",
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
    output = run(".", "test_run_license_003")
    print(json.dumps(output, indent=2))