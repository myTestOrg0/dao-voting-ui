"""Interpret live CLI/API files; HTTP and process execution stay in the Bash harness."""

import json
import hashlib
import os
import sys
from pathlib import Path

from wrapped_report import verdict

PACKAGE = "lodash"
VERSION = "4.17.11"
CVE = "CVE-2019-10744"
ALERT = "criticalCVE"


def read(path):
    return json.loads(path.read_text())


def phase(folder):
    report = read(folder / "report.json")
    assert report["verification_complete"] and not report["errors"], report
    cli_exit = int((folder / "cli-exit.txt").read_text())
    wrapper_exit = int((folder / "wrapper-exit.txt").read_text())
    assert cli_exit in (0, 1), f"CLI execution error/timeout: {cli_exit}"
    assert wrapper_exit == report["exit_code"]
    cli = read(folder / "cli-report.json")
    assert cli.get("ok") is True, cli
    cli = cli["data"]
    assert cli_exit == int(not cli["healthy"]), "CLI status does not agree with its report"
    policy = read(folder / "security-policy.json")["securityPolicyRules"]
    artifacts = read(folder / "scan-artifacts.json")
    package = [
        a
        for a in artifacts
        if a.get("type") == "npm" and a.get("name") == PACKAGE and a.get("version") == VERSION
    ]
    assert len(package) == 1, "Expected exactly one target component"
    (folder / "target-artifact.json").write_text(json.dumps(package[0], indent=2))
    critical = [a for a in package[0]["alerts"] if a["type"] == ALERT]
    assert (
        len(critical) == 1 and critical[0]["props"]["cveId"] == CVE
    ), "CLI groups by type; target must be unique"
    findings = read(folder / "findings.json")
    target = [
        f
        for f in findings
        if f["package"] == PACKAGE and f["version"] == VERSION and f["id"] == CVE
    ]
    assert len(target) == 1
    control = {
        f["id"]: f["action"]
        for f in findings
        if f["package"] == PACKAGE
        and f["version"] == VERSION
        and f["id"] in ("CVE-2020-8203", "CVE-2021-23337")
    }
    assert len(control) == 2
    target_tree = cli.get("alerts", {}).get("npm", {}).get(PACKAGE, {}).get(VERSION, {})
    cli_actions = []

    def walk(value):
        if isinstance(value, dict):
            if value.get("type") == ALERT and "policy" in value:
                cli_actions.append(value["policy"])
            else:
                for child in value.values():
                    walk(child)

    walk(target_tree)
    result = {
        "phase": folder.name,
        "scan_id": report["scan_id"],
        "commit": report["commit"],
        "policy_action": policy[ALERT]["action"],
        "policy_rules_sha256": hashlib.sha256(
            json.dumps(policy, sort_keys=True).encode()
        ).hexdigest(),
        "server_action": target[0]["action"],
        "server_action_source": target[0]["action_source"],
        "cli_target_actions": cli_actions,
        "cli_target_reported": bool(cli_actions),
        "cli_process_exit": cli_exit,
        "wrapper_process_exit": wrapper_exit,
        "wrapper_target_exit": verdict(target),
        "controls": control,
        "components": report["components"],
        "cli_healthy": cli["healthy"],
    }
    (folder / "comparison.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


def request(folder):
    before = read(folder / "before/comparison.json")
    assert before["policy_action"] == before["server_action"] == "warn"
    assert before["cli_target_reported"] and before["cli_target_actions"] == ["warn"]
    marker = os.environ["GITHUB_RUN_ID"] + "-" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    payload = {
        "reason": "other",
        "reason_text": "Temporary comparison test; not an applicability assessment",
        "comment": "Temporary CLI/server comparison " + marker,
        "vigil_selector": {
            "location.repo": os.environ["SOCKET_REPO"],
            "artifact.type": "npm",
            "artifact.namespace": "",
            "artifact.name": PACKAGE,
            "artifact.version": VERSION,
            "finding.alertType": ALERT,
            "finding.cveId": CVE,
        },
    }
    (folder / "request.json").write_text(json.dumps(payload, indent=2))


def result(folder):
    phases = [read(folder / name / "comparison.json") for name in ("before", "active", "revoked")]
    before, active, revoked = phases
    assert [p["server_action"] for p in phases] == ["warn", "ignore", "warn"], phases
    assert active["server_action_source"]["type"] == "resolution"
    assert [p["wrapper_target_exit"] for p in phases] == [1, 0, 1]
    assert len({p["commit"] for p in phases}) == 1
    assert all(p["policy_action"] == before["policy_action"] for p in phases)
    assert len({p["policy_rules_sha256"] for p in phases}) == 1
    assert all(p["controls"] == before["controls"] for p in phases)
    assert all(p["components"] == before["components"] for p in phases)
    assert read(folder / "deleted.json")["deleted"]
    summary = {
        "target": f"{PACKAGE}@{VERSION} / {CVE}",
        "phases": phases,
        "resolution_deleted": True,
        "policy_modified": False,
        "cli_honors_resolution_in_report": not active["cli_target_reported"],
        "note": "The target has policy Warn: native CLI exit 0 alone does not prove suppression. Full wrapper can stay red due to other Warn findings.",
    }
    (folder / "comparison.json").write_text(json.dumps(summary, indent=2))
    lines = [
        "# Native exception: CLI versus wrapper",
        "",
        "| Phase | Policy | Server action | CLI target | CLI exit | Wrapper full exit | Wrapper target exit |",
        "|---|---|---|---|---:|---:|---:|",
    ]
    for p in phases:
        action = ", ".join(p["cli_target_actions"]) or "not reported"
        lines.append(
            f"| {p['phase']} | {p['policy_action']} | {p['server_action']} | {action} | {p['cli_process_exit']} | {p['wrapper_process_exit']} | {p['wrapper_target_exit']} |"
        )
    lines += [
        "",
        summary["note"],
        "",
        "Temporary resolution deleted and GET returned HTTP 404. Policy was not modified.",
    ]
    markdown = "\n".join(lines) + "\n"
    (folder / "comparison.md").write_text(markdown)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
        stream.write(markdown)
    print(json.dumps(summary))


if __name__ == "__main__":
    command, path = sys.argv[1:]
    {"phase": phase, "request": request, "result": result}[command](Path(path))
