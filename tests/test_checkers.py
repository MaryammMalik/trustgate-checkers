"""
TrustGate — Checker Test Suite
Runs each checker against the fixtures in tests/fixtures/ and asserts
expected findings (or lack thereof).
"""

import pathlib
import pytest
import sys

# Make sure the project root is on the path so imports work whether
# pytest is run from the repo root or from inside tests/.
ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from backend.checkers import dependency_verifier, license_checker  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


# ---------------------------------------------------------------------------
# license_checker tests
# ---------------------------------------------------------------------------

def test_clean_branch_no_license_findings():
    """A clean repo should produce zero license findings."""
    result = license_checker.run(str(FIXTURES / "clean_branch_a"), "t_lic_clean")
    assert result["status"] == "success"
    assert result["findings"] == [], (
        f"Expected no findings for clean_branch_a, got: {result['findings']}"
    )


def test_dirty_gpl_header_flagged():
    """A file with a GPL header should be flagged as a high-severity finding."""
    result = license_checker.run(str(FIXTURES / "dirty_gpl_header"), "t_lic_gpl")
    assert result["status"] == "success"
    assert len(result["findings"]) > 0, "Expected at least one finding for GPL header"
    severities = {f["severity"] for f in result["findings"]}
    assert "high" in severities, (
        f"Expected a high-severity finding, got severities: {severities}"
    )


# ---------------------------------------------------------------------------
# dependency_verifier tests
# ---------------------------------------------------------------------------

def test_clean_branch_no_dep_findings():
    """A clean repo with only stdlib imports should produce zero dep findings."""
    result = dependency_verifier.run(str(FIXTURES / "clean_branch_b"), "t_dep_clean")
    assert result["status"] == "success"
    assert result["findings"] == [], (
        f"Expected no findings for clean_branch_b, got: {result['findings']}"
    )


def test_dirty_hallucinated_dep_flagged():
    """A file importing a non-existent PyPI package should be flagged."""
    result = dependency_verifier.run(
        str(FIXTURES / "dirty_hallucinated_dep"), "t_dep_hallucinated"
    )
    assert result["status"] == "success"
    assert len(result["findings"]) > 0, (
        "Expected at least one finding for hallucinated dependency"
    )
    evidence_texts = [f["evidence"] for f in result["findings"]]
    assert any("fakepackagexyz123" in e for e in evidence_texts), (
        f"Expected finding mentioning 'fakepackagexyz123', got: {evidence_texts}"
    )
