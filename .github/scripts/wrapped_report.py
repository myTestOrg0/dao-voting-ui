"""Normalize server findings and write the read-only Actions report."""

import html
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

from wrapped_vex import effective_document, evaluate
from wrapped_vex_sources import load_sources

ACTION_RANK = {"error": 0, "warn": 1, "monitor": 2, "ignore": 3, "unknown": 4}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def parse_cli_result(text):
    """CLI progress messages can precede its JSON result, even with --json."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            value, _ = decoder.raw_decode(text[match.start() :])
        except ValueError:
            continue
        if isinstance(value, dict) and isinstance(value.get("ok"), bool):
            return value
    raise ValueError("Socket CLI did not return a recognizable JSON result")


def md(value):
    value = html.escape(str(value), quote=False).replace("\n", " ").replace("\r", " ")
    return re.sub(r"([\\`*_\[\]|])", r"\\\1", value)


def package_name(artifact):
    namespace = artifact.get("namespace") or ""
    name = artifact.get("name") or "unknown"
    return f"{namespace.rstrip('/')}/{name}" if namespace else name


def collect_findings(artifacts):
    findings = {}
    manifests = set()
    components = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not artifact.get("name"):
            continue
        name = package_name(artifact)
        component = (artifact.get("type", "unknown"), name, artifact.get("version", "unknown"))
        components.add(component)
        for manifest in artifact.get("manifestFiles") or []:
            if isinstance(manifest, dict) and manifest.get("file"):
                manifests.add(manifest["file"])
        for alert in artifact.get("alerts") or []:
            props = alert.get("props") or {}
            alert_type = alert.get("type", "unknown")
            is_cve = alert.get("category") == "vulnerability" or "cve" in alert_type.lower()
            identifier = props.get("cveId") or props.get("ghsaId") or alert_type
            # One row per component/version/advisory; non-CVE capabilities group by type.
            key = (*component, identifier)
            action = alert.get("action", "unknown")
            if action == "block":
                action = "error"
            action = action if action in ACTION_RANK else "unknown"
            severity = str(props.get("severity") or alert.get("severity") or "unknown").lower()
            severity = {"middle": "medium", "moderate": "medium", "mild": "low"}.get(
                severity, severity
            )
            severity = severity if severity in SEVERITY_RANK else "unknown"
            finding = {
                "ecosystem": component[0],
                "package": name,
                "version": component[2],
                "id": identifier,
                "type": alert_type,
                "vulnerability": is_cve,
                "severity": severity,
                "action": action,
                "fixed_version": props.get("firstPatchedVersionIdentifier") or "No data",
                "ghsa": props.get("ghsaId") or "",
                "action_source": alert.get("actionSource"),
                "reachability": alert.get("reachability"),
            }
            previous = findings.get(key)
            rank = (ACTION_RANK[action], SEVERITY_RANK[severity])
            previous_rank = (99, 99)
            if previous is not None:
                previous_rank = (
                    ACTION_RANK[previous["action"]],
                    SEVERITY_RANK[previous["severity"]],
                )
            if rank < previous_rank:
                findings[key] = finding
    rows = sorted(findings.values(), key=finding_order)
    return rows, sorted(manifests), len(components)


def finding_order(finding):
    return (
        ACTION_RANK[finding["action"]],
        SEVERITY_RANK[finding["severity"]],
        finding["package"],
        finding["version"],
        finding["id"],
    )


def verdict(rows):
    """Only Block/Warn fail; Monitor remains visible and successful."""
    if any(row["action"] == "unknown" for row in rows):
        return 2
    return int(any(row["action"] in ("error", "warn") for row in rows))


def table(rows):
    lines = [
        "| Package | Version | Advisory / alert | Severity | Action | Fix |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        values = [
            row[key] for key in ("package", "version", "id", "severity", "action", "fixed_version")
        ]
        lines.append("| " + " | ".join(md(value) for value in values) + " |")
    return "\n".join(lines)


def render(report, rows):
    counts = Counter(row["action"] for row in rows)
    status = {
        0: "Passed: no Block/Warn findings",
        1: "Failed: Block/Warn findings",
        2: "Verification incomplete",
    }[report["exit_code"]]
    lines = [
        "## Socket scan",
        "",
        f"**{status}**",
        "",
        "### Findings",
        "",
        "Monitor findings are reported but do not fail this check.",
        "",
        "| Components | Block | Warn | Monitor | Ignore |",
        "|---:|---:|---:|---:|---:|",
        f"| {report.get('components', 0)} | {counts['error']} | {counts['warn']} | {counts['monitor']} | {counts['ignore']} |",
        "",
    ]
    if not report["verification_complete"]:
        lines += [
            "**Findings are unavailable or partial. Zero counts do not establish a clean scan.**",
            "",
        ]
    if report.get("scan_id"):
        lines += [
            f"[Socket report](https://socket.dev/dashboard/org/{report['org']}/sbom/{report['scan_id']})",
            f"Commit: `{report['commit']}` · branch: `{md(report['branch'])}`",
            "",
        ]
    if report.get("dashboard_note"):
        lines += [md(report["dashboard_note"]), ""]
    for title, actions in [
        ("Block and Warn", {"error", "warn"}),
        ("Monitor (non-blocking)", {"monitor"}),
    ]:
        selected = [row for row in rows if row["action"] in actions]
        if selected:
            lines += [
                f"<details><summary>{title}: {len(selected)}</summary>",
                "",
                table(selected),
                "",
                "</details>",
                "",
            ]
    lines += ["### Reachability and fallback", ""]
    if report.get("fallback"):
        lines += [
            "**Fallback to regular SCA. Full application reachability did not complete.**",
            md(report["fallback"].get("message", "Reachability analysis failed.")),
            "",
        ]
    elif report.get("reach_requested"):
        lines += [
            "Full application reachability requested; no global fallback was reported. Individual CVEs may still have unknown or unsupported reachability.",
            "",
        ]
    else:
        lines += ["Manifest SCA; full application reachability was not requested.", ""]
    lines += ["### Infrastructure and verification errors", ""]
    lines += [md(error) for error in report["errors"]] or ["None."]
    if report.get("sources"):
        lines += [
            "",
            "### VEX sources",
            "",
            "| Source | Eligible | Revision / reason |",
            "|---|---|---|",
        ]
        for source in report["sources"]:
            detail = source.get("revision") or source.get("reason", "")
            lines.append(f"| {md(source['name'])} | {source['eligible']} | {md(detail)} |")
        chosen = [row for row in rows if row.get("vex")]
        if chosen:
            lines += [
                "",
                "| Package / advisory | Source | Status | Evidence |",
                "|---|---|---|---|",
            ]
            for row in chosen:
                vex = row["vex"]
                url = vex.get("evidence_url", "")
                evidence = f"[VEX document]({url})" if url else md(vex["document_id"])
                lines.append(
                    f"| {md(row['package'])} / {md(row['id'])} | {md(vex['source'])} | {md(vex['status'])} | {evidence} |"
                )
    return "\n".join(lines) + "\n"


def save(folder, report, rows):
    for name, data in [("report.json", report), ("findings.json", rows)]:
        (folder / name).write_text(json.dumps(data, indent=2))
    content = render(report, rows)
    (folder / "summary.md").write_text(content)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write(content)
    for row in rows:
        if row["action"] != "ignore":
            print(
                "FINDING | "
                + " | ".join(
                    md(row[key]) for key in ("package", "version", "id", "severity", "action")
                )
            )
    print(
        f"Socket verdict: exit={report['exit_code']}; fallback={bool(report.get('fallback'))}; errors={len(report['errors'])}"
    )


def read_creation(folder):
    result = parse_cli_result((folder / "cli-output.log").read_text())
    scan_id = (result.get("data") or {}).get("id", "")
    if not result["ok"] or not re.fullmatch(r"[A-Za-z0-9-]+", scan_id):
        raise ValueError("Socket did not return a valid scan ID")
    fallback = result.get("reachabilityFallback")
    if fallback is not None and not isinstance(fallback, dict):
        raise ValueError("Malformed reachability fallback metadata")
    return scan_id, fallback


def verify_baseline(folder, report):
    """The legacy SCA head and the typed reachability head are different."""
    repository = json.loads((folder / "repository.json").read_text())
    head = {
        "default_branch": repository.get("default_branch"),
        "head_full_scan_id": repository.get("head_full_scan_id"),
    }
    head["matches"] = (
        head["default_branch"] == "develop" and head["head_full_scan_id"] == report["scan_id"]
    )
    if not head["matches"] and report["reach_requested"] and not report["fallback"]:
        metadata = json.loads((folder / "metadata.json").read_text())
        expected = {
            "scan_type": "socket_tier1",
            "branch": report["branch"],
            "commit_hash": report["commit"],
        }
        if head["default_branch"] != "develop":
            raise ValueError("Socket default branch is not develop")
        for field, value in expected.items():
            if metadata.get(field) != value:
                raise ValueError(f"Reachability metadata does not match {field}")
        note = (
            "Reachability publication requested; typed head is not exposed by the legacy "
            "repository API. Metadata verified; active typed head is not independently confirmed."
        )
        head.update(
            matches=None,
            scan_type="socket_tier1",
            scan_id=report["scan_id"],
            context_verified=True,
            note=note,
        )
        report["dashboard_note"] = note
    (folder / "baseline-head.json").write_text(json.dumps(head, indent=2))
    if head["matches"] is False:
        raise ValueError("Socket dashboard head does not match the develop scan")


def apply_vex(folder, rows, target):
    config_file = Path(__file__).parents[1] / "socket-vex-sources.json"
    config = json.loads(config_file.read_text())
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Expected the exact GitHub owner/repository identity")
    # Derive scope from the running repository, never a copied config's product_id.
    product_id = f"https://github.com/{repository}"
    # Keep this central VEX comparison independent from native Socket resolutions.
    for row in rows:
        if row["vulnerability"] and row["action"] == "ignore":
            row["server_action_before_vex"] = "ignore"
            row["action"] = "monitor"
    sources = load_sources(config, rows, target)
    effective = evaluate(rows, sources, product_id)
    document = effective_document(effective, product_id)
    if document is not None:
        (folder / "effective-vex.json").write_text(json.dumps(document, indent=2))
    provenance = []
    for source in sources:
        entry = source.copy()
        del entry["document"]
        provenance.append(entry)
    (folder / "vex-provenance.json").write_text(json.dumps(provenance, indent=2))
    return effective, provenance


def main():
    """Interpret downloaded files. The workflow owns commands, downloads and credentials."""
    folder = Path(os.environ["SOCKET_RESULTS_DIR"])
    folder.mkdir(parents=True, exist_ok=True)
    rows = []
    report = {
        "org": os.environ["SOCKET_ORG"],
        "branch": os.environ["SCAN_BRANCH"],
        "commit": os.environ.get("SCAN_COMMIT", ""),
        "mode": os.environ.get("SOCKET_MODE", "policy"),
        "reach_requested": os.environ.get("SOCKET_REACH") == "true",
        "fallback": None,
        "errors": [],
        "verification_complete": False,
        "exit_code": 2,
    }
    phase = "scan creation"
    try:
        if os.environ.get("SCAN_OUTCOME") != "success":
            raise ValueError("Scan command did not complete successfully; see the scan step")
        report["scan_id"], report["fallback"] = read_creation(folder)

        phase = "Socket result collection"
        if os.environ.get("DOWNLOAD_OUTCOME") != "success":
            raise ValueError("Report download did not complete; see the curl step")
        artifacts = []
        for line in (folder / "scan-artifacts.ndjson").read_text().splitlines():
            if line.strip():
                artifacts.append(json.loads(line))
        (folder / "scan-artifacts.json").write_text(json.dumps(artifacts))
        rows, _, report["components"] = collect_findings(artifacts)
        if not report["components"]:
            raise ValueError("Socket returned no components; coverage cannot be verified")
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise ValueError("Invalid Socket component JSON")
            for alert in artifact.get("alerts") or []:
                if alert.get("action") not in ("error", "block", "warn", "monitor", "ignore"):
                    raise ValueError("Unrecognized server action")

        if report["mode"] == "vex":
            phase = "VEX verification"
            if os.environ.get("VEX_OUTCOME") != "success":
                raise ValueError("VEX snapshot download did not complete; see the VEX step")
            target = "application" if report["reach_requested"] else "manifest"
            rows, report["sources"] = apply_vex(folder, rows, target)

        if os.environ.get("SOCKET_PUBLISH_BASELINE") == "true":
            phase = "dashboard head verification"
            verify_baseline(folder, report)
        report["exit_code"] = verdict(rows)
        report["verification_complete"] = True
        report["status"] = "fallback" if report["fallback"] else "completed"
    except (ValueError, OSError, KeyError, TypeError) as error:
        report["status"] = "verification_incomplete"
        report["errors"].append(f"{phase}: {error}")
    save(folder, report, rows)
    return report["exit_code"]


if __name__ == "__main__":
    if sys.argv[1:] == ["scan-id"]:
        scan_id, _ = read_creation(Path(os.environ["SOCKET_RESULTS_DIR"]))
        print(scan_id)
    else:
        raise SystemExit(main())
