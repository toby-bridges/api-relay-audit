"""Dual-distribution invariant regression test.

The repo ships two parallel versions of the audit tool:

    - ``scripts/audit.py`` (modular, uses ``api_relay_audit/*.py``)
    - ``audit.py`` at repo root (standalone, zero-dep, curl-only)

Any change to one must be mirrored into the other. This test slices the
risk-matrix block from both files and asserts they are character-identical
so that drift is caught immediately.
"""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _extract_risk_matrix(path: Path) -> str:
    """Slice the risk-matrix block between the ``# Overall rating`` comment
    and the following ``# Output`` comment. Both files MUST contain both
    markers, otherwise the test is broken and should fail loudly.
    """
    text = path.read_text(encoding="utf-8")
    start_marker = "    # Overall rating\n"
    end_marker = "    # Output\n"
    start = text.find(start_marker)
    end = text.find(end_marker, start)
    if start == -1:
        raise AssertionError(f"Could not find '# Overall rating' marker in {path}")
    if end == -1:
        raise AssertionError(f"Could not find '# Output' marker in {path}")
    return text[start:end]


def test_risk_matrix_character_identical():
    """Regression: the risk matrix code in scripts/audit.py and audit.py MUST
    be character-identical. If this test fails, one of the two was updated
    without the other and the dual-distribution invariant is broken.
    """
    modular = _extract_risk_matrix(REPO_ROOT / "scripts" / "audit.py")
    standalone = _extract_risk_matrix(REPO_ROOT / "audit.py")
    assert modular == standalone, (
        "Risk matrix drift between scripts/audit.py and audit.py. "
        "Update both files so they are character-identical."
    )
