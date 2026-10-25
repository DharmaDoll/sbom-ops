"""Load the bundled, fixed reference table; no remote policy retrieval."""

import json
from functools import lru_cache
from importlib.resources import files

from sbom_ops.domain.triage_reference import ReferencePolicy


@lru_cache(maxsize=1)
def load_reference_policy() -> ReferencePolicy:
    payload = (
        files("sbom_ops")
        .joinpath("data/bod_26_04_reference.json")
        .read_text(encoding="utf-8")
    )
    return ReferencePolicy.from_dict(json.loads(payload))
