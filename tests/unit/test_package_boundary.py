from __future__ import annotations

import ast
import tomllib
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]
PRODUCT_ROOT = REPOSITORY_ROOT / "src" / "sbom_ops"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    return imported


def test_product_does_not_import_repository_lab() -> None:
    violations = {
        str(path.relative_to(REPOSITORY_ROOT)): sorted(
            module
            for module in _imports(path)
            if module == "dt_lab" or module.startswith("dt_lab.")
        )
        for path in PRODUCT_ROOT.rglob("*.py")
    }

    assert not {path: imports for path, imports in violations.items() if imports}


def test_product_package_exposes_no_lab_console_script() -> None:
    pyproject = tomllib.loads(
        (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        "src/sbom_ops"
    ]
    assert set(pyproject["project"]["scripts"]) == {"sbom-ops"}
