"""Match exact npm identities and choose the first applicable OpenVEX statement."""

import copy
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

STATUSES = {"affected", "not_affected", "fixed", "under_investigation"}
JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


def npm_identity(purl):
    if not isinstance(purl, str) or not purl.startswith("pkg:npm/"):
        return None
    parsed = urlsplit(purl)
    # Qualifiers/subpaths require matching metadata not present in this POC input.
    if parsed.query or parsed.fragment:
        return None
    name, separator, version = purl[len("pkg:npm/") :].rpartition("@")
    if not separator or not name or not version:
        return None
    return unquote(name), unquote(version)


def aliases(value):
    return set(re.findall(r"CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", str(value)))


def parse_time(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("VEX timestamp must include timezone")
    return result


def load_source(name, path, now):
    return parse_source(name, Path(path).read_bytes(), now)


def parse_source(name, raw, now):
    document = json.loads(raw)
    if document.get("@context") != "https://openvex.dev/ns/v0.2.0":
        raise ValueError("Unsupported OpenVEX context")
    if (
        not document.get("@id")
        or not document.get("author")
        or not isinstance(document.get("version"), int)
        or document["version"] < 1
    ):
        raise ValueError("Missing VEX identity, author or version")
    if parse_time(document["timestamp"]) > now:
        raise ValueError("VEX document timestamp is in the future")
    if not isinstance(document.get("statements"), list):
        raise ValueError("VEX statements must be an array")
    # Optional organization extension; expiration is not an OpenVEX standard field.
    expired = bool(document.get("x-poc-expires") and parse_time(document["x-poc-expires"]) <= now)
    return {
        "name": name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "document_id": document["@id"],
        "expired": expired,
        "document": document,
    }


def matching_statement(source, finding, product_id):
    if source["expired"]:
        return None
    matches = []
    identity = finding["package"], finding["version"]
    ids = aliases(finding["id"]) | aliases(finding.get("ghsa", ""))
    for statement in source["document"]["statements"]:
        vulnerability = statement.get("vulnerability") or {}
        if not ids.intersection(
            aliases(vulnerability.get("name", "")) | aliases(vulnerability.get("@id", ""))
        ):
            continue
        applicable = False
        for product in statement.get("products") or []:
            top = product.get("@id")
            # Our exceptions must name the application repository explicitly.
            # Vendor package statements are considered only after image-scope checks.
            if source["name"] != "own" and npm_identity(top) == identity:
                applicable = True
            if top == product_id:
                applicable |= any(
                    npm_identity(component.get("@id")) == identity
                    for component in product.get("subcomponents") or []
                )
        if not applicable:
            continue
        status = statement.get("status")
        if status not in STATUSES:
            raise ValueError("Unknown VEX status for a matching finding")
        if (
            status == "not_affected"
            and statement.get("justification") not in JUSTIFICATIONS
            and not statement.get("impact_statement")
        ):
            raise ValueError("not_affected requires valid justification or impact statement")
        if status == "affected" and not statement.get("action_statement"):
            raise ValueError("affected requires an action statement")
        matches.append(statement)
    if len({s["status"] for s in matches}) > 1:
        raise ValueError("Conflicting VEX statuses in the same source")
    return matches[0] if matches else None


def evaluate(findings, sources, product_id):
    if any(f.get("action") not in ("error", "warn", "monitor", "ignore") for f in findings):
        raise ValueError(
            "Unrecognized scanner action; VEX cannot turn incomplete verification into success"
        )
    effective = copy.deepcopy(findings)
    for finding in effective:
        finding["original_action"] = finding["action"]
        if not finding.get("vulnerability") or finding.get("ecosystem") != "npm":
            continue
        for source in sources:
            statement = matching_statement(source, finding, product_id)
            if statement is None:
                continue
            finding["vex"] = {
                "status": statement["status"],
                "source": source["name"],
                "document_id": source["document_id"],
                "sha256": source["sha256"],
                "statement_id": statement.get("@id"),
                "evidence_url": statement.get("evidence_url"),
                "status_notes": statement.get("status_notes"),
                "statement": copy.deepcopy(statement),
                "reason": statement.get("impact_statement")
                or statement.get("justification")
                or statement.get("action_statement")
                or statement.get("status_notes")
                or statement["status"].replace("_", " "),
            }
            if statement["status"] in ("not_affected", "fixed"):
                finding["action"] = "ignore"
            # affected/under_investigation stop lower-priority suppressions.
            break
    return effective


def effective_document(findings, product_id):
    """One resolved statement per finding, scoped only to this application repository."""
    statements = []
    for finding in findings:
        decision = finding.get("vex")
        if decision is None:
            continue
        statement = copy.deepcopy(decision["statement"])
        statement.pop("evidence_url", None)
        statement.pop("@id", None)
        package = quote(finding["package"], safe="/")
        version = quote(finding["version"], safe="")
        statement["products"] = [
            {
                "@id": product_id,
                "subcomponents": [{"@id": f"pkg:npm/{package}@{version}"}],
            }
        ]
        evidence = decision.get("evidence_url") or decision["document_id"]
        notes = statement.get("status_notes", "")
        statement["status_notes"] = (
            f"{notes}\nSelected source: {decision['source']}; evidence: {evidence}".strip()
        )
        if statement not in statements:
            statements.append(statement)
    if not statements:
        return None
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": "myTestOrg0 VEX resolver",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "statements": statements,
    }
