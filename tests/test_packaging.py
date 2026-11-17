"""Keep packaging metadata, the CI matrix and the README badge in step."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


@pytest.fixture(autouse=True)
def _needs_checkout():
    # The sdist ships tests/ but not .github/, so outside a git checkout
    # there is no workflow to compare with.
    if not WORKFLOW.exists():
        pytest.skip("CI workflow not present (running from an sdist?)")


def _ci_python_versions() -> list[str]:
    text = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(r"^\s*python-version: \[(?P<versions>[^\]]*)\]", text, re.M)
    assert match, "no python-version list in the CI matrix"
    return [v.strip().strip("\"'") for v in match["versions"].split(",")]


def _pyproject() -> dict:
    tomllib = pytest.importorskip("tomllib")  # standard library from 3.11
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def test_ci_tests_every_supported_python_version():
    prefix = "Programming Language :: Python :: "
    classified = [
        c.removeprefix(prefix)
        for c in _pyproject()["classifiers"]
        if re.fullmatch(re.escape(prefix) + r"3\.\d+", c)
    ]

    assert sorted(classified, key=_key) == sorted(_ci_python_versions(), key=_key)


def test_requires_python_starts_at_the_oldest_tested_version():
    oldest = min(_ci_python_versions(), key=_key)

    assert _pyproject()["requires-python"] == f">={oldest}"


def test_readme_badge_points_at_the_ci_workflow():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert f"actions/workflows/{WORKFLOW.name}/badge.svg" in readme


def test_changelog_has_an_entry_for_the_current_version():
    from hashident import __version__

    changelog = ROOT / "CHANGELOG.md"
    assert changelog.exists(), "CHANGELOG.md is missing"
    assert re.search(
        rf"^## \[{re.escape(__version__)}\] - \d{{4}}-\d{{2}}-\d{{2}}$",
        changelog.read_text(encoding="utf-8"),
        re.M,
    ), f"CHANGELOG.md has no entry for {__version__}"
