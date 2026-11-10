"""Interpret native Python reports and captured API responses; no HTTP or process execution."""

import hashlib
import json
import os
import sys
from pathlib import Path

PACKAGE = "lodash"
VERSION = "4.17.11"
CVE = "CVE-2019-10744"
ALERT = "criticalCVE"


def read(path):
    return json.loads(path.read_text())


def phase(folder):
    code = int((folder / "python-exit.txt").read_text())
    assert code in (0, 1), code
    report = read(folder / "python-report.json")
    assert code == int(report["scan_failed"]), report
    target = [
        a
        for a in report["new_alerts"]
        if a["pkg_name"] == PACKAGE
        and a["pkg_version"] == VERSION
        and (a.get("props") or {}).get("cveId") == CVE
    ]
    actions = [
        (
            "error"
            if a.get("error")
            else "warn" if a.get("warn") else "ignore" if a.get("ignore") else "monitor"
        )
        for a in target
    ]
    artifacts = [
        json.loads(line)
        for line in (folder / "scan-artifacts.ndjson").read_text().splitlines()
        if line.strip()
    ]
    packages = [
        a
        for a in artifacts
        if a.get("type") == "npm" and a.get("name") == PACKAGE and a.get("version") == VERSION
    ]
    assert len(packages) == 1
    package = packages[0]
    alerts = [a for a in package["alerts"] if (a.get("props") or {}).get("cveId") == CVE]
    assert len(alerts) == 1
    (folder / "target-artifact.json").write_text(json.dumps(package, indent=2))
    controls = {
        (a.get("props") or {}).get("cveId"): a["action"]
        for a in package["alerts"]
        if (a.get("props") or {}).get("cveId") in ("CVE-2020-8203", "CVE-2021-23337")
    }
    assert len(controls) == 2
    policy = read(folder / "security-policy.json")["securityPolicyRules"]
    text = (folder / "python-comments.ndjson").read_text().strip()
    decoder = json.JSONDecoder()
    comments = []
    while text:
        value, end = decoder.raw_decode(text)
        comments.append(value)
        text = text[end:].strip()
    assert len(comments) == 1, "Expected one native Python security comment"
    comment = comments[0]
    assert report["full_scan_id"] in comment["body"], "Comment does not link this phase scan"
    assert (
        "@SocketSecurity ignore" not in comment["body"]
    ), "Suppression instructions must be disabled"
    (folder / "python-pr-comment.md").write_text(comment["body"])
    result = {
        "phase": folder.name,
        "scan_id": report["full_scan_id"],
        "commit": report["commit_sha"],
        "policy_action": policy[ALERT]["action"],
        "server_action": alerts[0]["action"],
        "server_action_source": alerts[0].get("actionSource"),
        "python_target_reported": bool(target),
        "python_target_actions": actions,
        "python_process_exit": code,
        "controls": controls,
        "components": len(
            {
                (a.get("type"), a.get("namespace"), a.get("name"), a.get("version"))
                for a in artifacts
                if a.get("name")
            }
        ),
        "policy_rules_sha256": hashlib.sha256(
            json.dumps(policy, sort_keys=True).encode()
        ).hexdigest(),
        "comment_id": comment["id"],
        "comment_url": comment["html_url"],
        "disable_ignore": True,
    }
    (folder / "comparison.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


def request(folder):
    before = read(folder / "before/comparison.json")
    assert before["policy_action"] == before["server_action"] == "warn"
    assert before["python_target_reported"] and before["python_target_actions"] == ["warn"]
    marker = os.environ["GITHUB_RUN_ID"] + "-" + os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    payload = {
        "reason": "other",
        "reason_text": "Temporary comparison test; not an applicability assessment",
        "comment": "Temporary Python CLI native resolution comparison " + marker,
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
    assert [p["server_action"] for p in phases] == ["warn", "ignore", "warn"]
    assert active["server_action_source"]["type"] == "resolution"
    assert [p["python_target_reported"] for p in phases] == [True, False, True], phases
    assert len({p["commit"] for p in phases}) == 1
    assert len({p["policy_rules_sha256"] for p in phases}) == 1
    assert len({p["comment_id"] for p in phases}) == 1
    assert all(p["controls"] == before["controls"] for p in phases)
    assert all(p["components"] == before["components"] for p in phases)
    assert read(folder / "deleted.json")["deleted"]
    result = {
        "target": f"{PACKAGE}@{VERSION} / {CVE}",
        "python_cli": "2.11.13",
        "phases": phases,
        "resolution_deleted": True,
        "policy_modified": False,
        "comment_suppression_disabled": True,
        "control_baseline": read(folder / "baseline.json")["full_scan_id"],
    }
    (folder / "comparison.json").write_text(json.dumps(result, indent=2))
    lines = [
        "# Native Python resolution lifecycle",
        "",
        "| Phase | Policy | Server | Python target | Python exit |",
        "|---|---|---|---|---:|",
    ]
    for p in phases:
        target = ", ".join(p["python_target_actions"]) or "not reported"
        lines.append(
            f"| {p['phase']} | {p['policy_action']} | {p['server_action']} | {target} | {p['python_process_exit']} |"
        )
    lines += [
        "",
        "Warn is non-blocking: exit 0 alone does not prove suppression. The target must disappear from the processed findings.",
        "Native PR comment was updated; --disable-ignore is enabled. Temporary resolution deleted and GET returned 404.",
    ]
    text = "\n".join(lines) + "\n"
    (folder / "comparison.md").write_text(text)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
        stream.write(text)
    print(json.dumps(result))


if __name__ == "__main__":
    command, path = sys.argv[1:]
    {"phase": phase, "request": request, "result": result}[command](Path(path))
