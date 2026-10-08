from __future__ import annotations

import ast
from pathlib import Path

LAB_ROOT = Path(__file__).parents[1]
LAB_SOURCE = LAB_ROOT / "src" / "dt_lab"
ALLOWED_PRODUCT_IMPORTS = {"sbom_ops.clients.http"}


def _product_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(
                alias.name
                for alias in node.names
                if alias.name == "sbom_ops" or alias.name.startswith("sbom_ops.")
            )
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and (node.module == "sbom_ops" or node.module.startswith("sbom_ops."))
        ):
            imported.add(node.module)
    return imported


def test_lab_only_reuses_the_generic_product_http_transport() -> None:
    imports = set().union(
        *(_product_imports(path) for path in LAB_SOURCE.rglob("*.py"))
    )

    assert imports == ALLOWED_PRODUCT_IMPORTS


def test_lab_has_one_durable_experiment_ledger_with_required_sections() -> None:
    ledger = (LAB_ROOT / "EXPERIMENTS.md").read_text(encoding="utf-8")

    assert "## Recording Rules" in ledger
    assert "## Entry Template" in ledger
    for heading in (
        "### Purpose",
        "### Performed",
        "### Observed Facts",
        "### Interpretation and Product Decision",
        "### Unverified",
        "### Local Evidence",
    ):
        assert heading in ledger


def test_lab_does_not_offer_immediate_cleanup_after_a_run() -> None:
    cli = (LAB_SOURCE / "cli.py").read_text(encoding="utf-8")
    spec = (LAB_ROOT.parents[1] / "SPEC.md").read_text(encoding="utf-8")

    assert "--cleanup-on-success" not in cli
    assert "Immediate automatic cleanup is prohibited" in spec
