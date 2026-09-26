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
from dotenv import load_dotenv

load_dotenv()

LICENSE_MARKERS = {
    "GPL": {
        "severity": "high",
        "patterns": [
            "GNU GENERAL PUBLIC LICENSE", "GPL-3.0", "GPL-2.0", "GPL-1.0",
            "licensed under the GPL", "GNU Lesser General Public License",
            "GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL", "AGPL-3.0",
            "LGPL", "LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
            "www.gnu.org/licenses", "version 3 of the License", "EUPL", "copyleft",
        ],
    },
    "Apache": {
        "severity": "medium",
        "patterns": [
            "Apache License", "Apache-2.0", "Apache-1.1", "Apache-1.0",
            "www.apache.org/licenses", "apache.org/licenses/LICENSE-2.0",
            "SPDX-License-Identifier: Apache",
        ],
    },
    "Proprietary": {
        "severity": "medium",
        "patterns": [
            "All Rights Reserved", "Proprietary and confidential",
            "Unauthorized copying of this file", "Do not distribute",
            "internal use only", "not for distribution", "trade secret",
        ],
    },
    "MPL": {
        "severity": "medium",
        "patterns": ["Mozilla Public License", "MPL-2.0", "MPL-1.1"],
    },
    "Restrictive": {
        "severity": "high",
        "patterns": [
            "Business Source License", "BUSL", "SSPL",
            "Server Side Public License", "Commons Clause",
            "Elastic License", "ELv2",
        ],
    },
}

AMBIGUOUS_HINTS = [
    "confidential", "proprietary", "SPDX-License-Identifier:",
    "creative commons", "CC BY-SA", "CC BY", "do not copy",
]

_SHORT_PATTERNS = {
    "AGPL", "LGPL", "LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
    "BUSL", "SSPL", "ELv2", "EUPL", "copyleft", "CC BY", "CC BY-SA",
}

_NEGATORS = ("not ", "non-", "no ", "without ", "isn't", "neither", "unlike")


def _marker_present(marker, text):
    m = marker.lower()
    t = text.lower()
    if marker in _SHORT_PATTERNS:
        return bool(re.search(r"\b" + re.escape(m) + r"\b", t))
    return m in t


def _is_negated(marker, line_text):
    lower = line_text.lower()
    return any(neg in lower for neg in _NEGATORS)


def scan_headers(path):
    findings = []
    ambiguous = []

    for p in pathlib.Path(path).rglob("*.py"):
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

                line_no = 1
                matched_line_text = ""
                for i, line in enumerate(lines, start=1):
                    if _marker_present(marker, line):
                        line_no = i
                        matched_line_text = line
                        break

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
    Send each ambiguous header snippet to Bob Shell (headless mode) and
    ask whether it's a real license violation.

    Requires the BOB_API_KEY environment variable to be set, and the
    `bob` CLI (Bob Shell) installed and on PATH.
    """
    import subprocess

    api_key = os.environ.get("BOB_API_KEY")
    if not api_key:
        return []

    confirmed_findings = []

    for case in ambiguous_cases:
        prompt = _ESCALATION_PROMPT.format(
            file=case["file"],
            snippet=case["snippet"],
        )
        try:
            result = subprocess.run(
                ["bob", "run", prompt, "-f", "json", "--accept-license"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = json.loads(result.stdout)
            reply = output.get("last_message", "").strip()
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            continue

        if not reply:
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