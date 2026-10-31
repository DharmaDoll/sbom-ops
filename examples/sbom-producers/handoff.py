"""Example orchestration using the product DT adapter; never writes an asset DB.

prepare is offline. upload requires --execute, a pre-created Project UUID and
protected environment credentials. Each attempt needs a new result filename.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from sbom_ops.clients.dependency_track import (
    DependencyTrackApiError,
    DependencyTrackClient,
)


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def validate_image(image: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("image must be a repository@sha256:digest reference")
    return image.rsplit("@", 1)[1]


def prepare(
    bom: Path,
    image: str,
    producer: str,
    revision: str,
    run: str,
    service: str = "checkout-api",
) -> dict[str, Any]:
    image_digest = validate_image(image)
    if producer not in {"npm", "uv"}:
        raise ValueError("unsupported producer")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", service):
        raise ValueError("invalid service ID")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("source revision must be the full Git commit")
    document = json.loads(bom.read_text())
    component = document.get("metadata", {}).get("component", {})
    if document.get("bomFormat") != "CycloneDX" or component.get("type") != "container":
        raise ValueError("requires a Trivy container Build SBOM, not a Source SBOM")
    # Trivy records the exact scan target here; fail closed on another image.
    if component.get("name") != image:
        raise ValueError("SBOM container name does not match the immutable scan target")
    components = document.get("components", [])
    required = "pkg:npm/picocolors@1.1.1" if producer == "npm" else "pkg:pypi/idna@3.10"
    if not any(c.get("purl") == required for c in components):
        raise ValueError("representative application dependency/PURL is missing")
    if not any(
        c.get("name") == "libc6" and "distro=debian-12" in c.get("purl", "")
        for c in components
    ):
        raise ValueError("representative Debian OS dependency/distro PURL is missing")
    return {
        "schema_version": 1,
        "service_id": service,
        "deployable_id": producer,
        "kind": "build",
        "image": image,
        "artifact_digest": image_digest,
        "platform": "linux/amd64",
        "source_revision": revision,
        "build_ref": run,
        "sbom_file": bom.name,
        "sbom_digest": digest(bom),
        "generator": "Trivy 0.69.3; image --format cyclonedx --scanners license",
        "observed_at": datetime.now(UTC).isoformat(),
        "project_name": f"{service}/{producer}",
        "project_version": image_digest,
        "project_uuid": None,
        "acceptance": "not_attempted",
        "bom_processing": "not_checked",
        "findings": "not_read",
        "analysis_complete": "unverified",
    }


def check_handoff(handoff: dict[str, Any], bom: Path) -> dict[str, Any]:
    expected = prepare(
        bom,
        handoff["image"],
        handoff["deployable_id"],
        handoff["source_revision"],
        handoff["build_ref"],
        handoff["service_id"],
    )
    for key in (
        "sbom_digest",
        "artifact_digest",
        "platform",
        "project_name",
        "project_version",
        "kind",
        "schema_version",
    ):
        if handoff[key] != expected[key]:
            raise ValueError(f"handoff mismatch: {key}")
    return expected


def upload(
    handoff: dict[str, Any],
    bom: Path,
    project_uuid: str,
    client: DependencyTrackClient,
    result: Path,
    *,
    timeout: float = 300,
    read_client: DependencyTrackClient | None = None,
) -> int:
    """Persist intent before mutation; no automatic retry after an unknown result."""
    UUID(project_uuid)
    expected = check_handoff(handoff, bom)
    state = {**expected, "project_uuid": project_uuid, "stage": "identity"}
    # Exclusive creation prevents silently replacing an earlier attempt.
    with result.open("x") as stream:
        json.dump(state, stream, indent=2)

    def save() -> None:
        temporary = result.with_suffix(result.suffix + ".tmp")
        temporary.write_text(json.dumps(state, indent=2) + "\n")
        temporary.replace(result)

    try:
        reader = read_client or client
        projects = reader.list_projects()
        matches = [
            p
            for p in projects
            if (
                p.name == expected["project_name"]
                and p.version == expected["project_version"]
            )
        ]
        if len(matches) != 1 or matches[0].uuid != project_uuid:
            raise ValueError("DT UUID/name/version is not a unique match; no upload")
        state.update(stage="upload", acceptance="unknown")
        save()
        response = client.upload_bom(project_uuid, bom)
        state.update(
            acceptance="accepted",
            token=response.token,
            stage="bom_processing",
            bom_processing="unknown",
        )
        save()
        client.wait_for_bom_processing(response.token, timeout=timeout)
        state.update(bom_processing="token_idle", stage="findings", findings="unknown")
        save()
        findings = reader.get_project_findings(project_uuid)
        state.update(findings="read", finding_count=len(findings), stage="recorded")
        save()
        return 0
    except (DependencyTrackApiError, ValueError):
        state["result"] = "failed_or_unknown"
        # Never serialize raw errors, credentials or response bodies.
        save()
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--bom", type=Path, required=True)
    p.add_argument("--image", required=True)
    p.add_argument("--producer", choices=("npm", "uv"), required=True)
    p.add_argument("--revision", required=True)
    p.add_argument("--run", required=True)
    p.add_argument("--service", default="checkout-api")
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("upload")
    p.add_argument("--handoff", type=Path, required=True)
    p.add_argument("--bom", type=Path, required=True)
    p.add_argument("--project", required=True)
    p.add_argument("--result", type=Path, required=True)
    p.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            data = prepare(
                args.bom,
                args.image,
                args.producer,
                args.revision,
                args.run,
                args.service,
            )
            with args.output.open("x") as stream:
                json.dump(data, stream, indent=2)
            return 0
        data = json.loads(args.handoff.read_text())
        if not args.execute:
            UUID(args.project)
            check_handoff(data, args.bom)
            print(
                "Inputs checked; DT identity and permissions are not checked; no upload"
            )
            return 0
        url = os.environ["SBOM_OPS_DT_BASE_URL"]
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("DT URL must be HTTPS without credentials/query/fragment")
        client = DependencyTrackClient(
            url,
            os.environ["SBOM_OPS_SBOM_UPLOAD_API_KEY"],
            max_retries=0,
        )
        reader = DependencyTrackClient(
            url,
            os.environ["SBOM_OPS_DT_API_KEY"],
            max_retries=0,
        )
        return upload(
            data, args.bom, args.project, client, args.result, read_client=reader
        )
    except (KeyError, OSError, ValueError, TypeError):
        print(
            "Invalid input/configuration or evidence could not be saved; check inputs"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
