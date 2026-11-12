"""Read the VEX snapshot already downloaded by the workflow's Bash step."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from wrapped_vex import parse_source

SCOPES = {
    "own": {"manifest", "application", "image", "dhi-image"},
    "docker-dhi": {"dhi-image"},
    "aqua": {"image", "dhi-image"},
}


def load_sources(config, findings, target):
    """Application scans read own VEX; image-only feeds are recorded as ineligible."""
    if target not in ("manifest", "application"):
        raise ValueError("This workflow supports manifest/application VEX, not image VEX")
    names = [source["name"] for source in config["sources"]]
    if names != ["own", "docker-dhi", "aqua"]:
        raise ValueError("Expected VEX priority own → Docker DHI → Aqua")

    folder = Path(os.environ["SOCKET_VEX_DIR"])
    revision = (folder / "revision.txt").read_text().strip()
    metadata = json.loads((folder / "vex-repository.json").read_text())
    versions = metadata.get("versions", [])
    if not any(version.get("spec_version") == "0.1" for version in versions):
        raise ValueError("Unsupported VEX repository specification")

    required_packages = set()
    for finding in findings:
        if finding["vulnerability"] and finding["ecosystem"] == "npm":
            required_packages.add(finding["package"])

    own = config["sources"][0]
    source_url = f"https://github.com/{own['repository']}/tree/{revision}"
    documents = []
    statements = []
    for path in sorted((folder / "pkg/npm").rglob("*.json")):
        relative = path.relative_to(folder)
        package = "/".join(unquote(part) for part in relative.parts[2:-1])
        if path.name == "manifest.json" or package not in required_packages:
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(folder.resolve()):
            raise ValueError("VEX document must be inside the trusted snapshot")
        raw = path.read_bytes()
        if len(raw) > 10_000_000:
            raise ValueError("VEX document exceeds size limit")
        document = parse_source("own", raw, datetime.now(timezone.utc))
        document_url = (
            f"https://github.com/{own['repository']}/blob/{revision}/{relative.as_posix()}"
        )
        documents.append(
            {
                "path": relative.as_posix(),
                "url": document_url,
                "id": document["document_id"],
                "sha256": document["sha256"],
                "expired": document["expired"],
            }
        )
        if not document["expired"]:
            for statement in document["document"]["statements"]:
                statement.setdefault("timestamp", document["document"]["timestamp"])
                statement["evidence_url"] = document_url
                statements.append(statement)

    sources = [
        {
            "name": "own",
            "repository": own["repository"],
            "eligible": True,
            "revision": revision,
            "documents": documents,
            "document_id": source_url,
            "sha256": hashlib.sha256(json.dumps(documents, sort_keys=True).encode()).hexdigest(),
            "expired": False,
            "document": {"statements": statements},
        }
    ]
    for item in config["sources"][1:]:
        name = item["name"]
        sources.append(
            {
                "name": name,
                "repository": item["repository"],
                "eligible": False,
                "reason": f'{name} requires {", ".join(sorted(SCOPES[name]))}; this scan targets {target}',
                "expired": False,
                "document": {"statements": []},
            }
        )
    return sources
