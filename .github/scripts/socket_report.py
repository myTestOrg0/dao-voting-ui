"""Normalize server findings and write the read-only Actions report."""
import html
import json
import os
import re
from collections import Counter
from pathlib import Path

ACTION_RANK = {"error": 0, "warn": 1, "monitor": 2, "ignore": 3, "unknown": 4}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def parse_cli_result(text):
    """CLI progress messages can precede its JSON result, even with --json."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            value, _ = decoder.raw_decode(text[match.start():])
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
            severity = {"middle": "medium", "moderate": "medium", "mild": "low"}.get(severity, severity)
            severity = severity if severity in SEVERITY_RANK else "unknown"
            finding = {
                "ecosystem": component[0], "package": name, "version": component[2],
                "id": identifier, "type": alert_type, "vulnerability": is_cve,
                "severity": severity, "action": action,
                "fixed_version": props.get("firstPatchedVersionIdentifier") or "No data",
                "ghsa": props.get("ghsaId") or "",
                "action_source": alert.get("actionSource"),
                "reachability": alert.get("reachability"),
            }
            previous = findings.get(key)
            if previous is None or (ACTION_RANK.get(action, 4), SEVERITY_RANK.get(severity, 4)) < (ACTION_RANK.get(previous["action"], 4), SEVERITY_RANK.get(previous["severity"], 4)):
                findings[key] = finding
    rows = sorted(findings.values(), key=lambda f: (ACTION_RANK.get(f["action"], 4), SEVERITY_RANK.get(f["severity"], 4), f["package"], f["version"], f["id"]))
    return rows, sorted(manifests), len(components)


def verdict(rows):
    """Only Block/Warn fail; Monitor remains visible and successful."""
    if any(row['action'] == 'unknown' for row in rows):
        return 2
    return int(any(row['action'] in ('error', 'warn') for row in rows))


def table(rows):
    lines = ['| Package | Version | Advisory / alert | Severity | Action | Fix |',
             '|---|---|---|---|---|---|']
    for row in rows:
        values = [row[key] for key in ('package', 'version', 'id', 'severity', 'action', 'fixed_version')]
        lines.append('| ' + ' | '.join(md(value) for value in values) + ' |')
    return '\n'.join(lines)


def render(report, rows):
    counts = Counter(row['action'] for row in rows)
    status = {0: 'Passed: no Block/Warn findings', 1: 'Failed: Block/Warn findings',
              2: 'Verification incomplete'}[report['exit_code']]
    lines = ['## Socket scan', '', f'**{status}**', '',
             '### Findings', '', 'Monitor findings are reported but do not fail this check.', '',
             '| Components | Block | Warn | Monitor | Ignore |', '|---:|---:|---:|---:|---:|',
             f"| {report.get('components', 0)} | {counts['error']} | {counts['warn']} | {counts['monitor']} | {counts['ignore']} |", '']
    if not report['verification_complete']:
        lines += ['**Findings are unavailable or partial. Zero counts do not establish a clean scan.**', '']
    if report.get('scan_id'):
        lines += [f"[Socket report](https://socket.dev/dashboard/org/{report['org']}/sbom/{report['scan_id']})",
                  f"Commit: `{report['commit']}` · branch: `{md(report['branch'])}`", '']
    for title, actions in [('Block and Warn', {'error', 'warn'}), ('Monitor (non-blocking)', {'monitor'})]:
        selected = [row for row in rows if row['action'] in actions]
        if selected:
            lines += [f'<details><summary>{title}: {len(selected)}</summary>', '', table(selected), '', '</details>', '']
    lines += ['### Reachability and fallback', '']
    if report.get('fallback'):
        lines += ['**Fallback to regular SCA. Full application reachability did not complete.**',
                  md(report['fallback'].get('message', 'Reachability analysis failed.')), '']
    elif report.get('reach_requested'):
        lines += ['Full application reachability requested; no global fallback was reported. Individual CVEs may still have unknown or unsupported reachability.', '']
    else:
        lines += ['Manifest SCA; full application reachability was not requested.', '']
    lines += ['### Infrastructure and verification errors', '']
    lines += [md(error) for error in report['errors']] or ['None.']
    if report.get('sources'):
        lines += ['', '### VEX sources', '', '| Source | Eligible | Revision / reason |', '|---|---|---|']
        for source in report['sources']:
            detail = source.get('revision') or source.get('reason', '')
            lines.append(f"| {md(source['name'])} | {source['eligible']} | {md(detail)} |")
        chosen = [row for row in rows if row.get('vex')]
        if chosen:
            lines += ['', '| Package / advisory | Source | Status |', '|---|---|---|']
            for row in chosen:
                lines.append(f"| {md(row['package'])} / {md(row['id'])} | {md(row['vex']['source'])} | {md(row['vex']['status'])} |")
    return '\n'.join(lines) + '\n'


def save(folder, report, rows):
    for name, data in [('report.json', report), ('findings.json', rows)]:
        (folder / name).write_text(json.dumps(data, indent=2))
    content = render(report, rows)
    (folder / 'summary.md').write_text(content)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write(content)
    for row in rows:
        if row['action'] != 'ignore':
            print('FINDING | ' + ' | '.join(md(row[key]) for key in ('package', 'version', 'id', 'severity', 'action')))
    print(f"Socket verdict: exit={report['exit_code']}; fallback={bool(report.get('fallback'))}; errors={len(report['errors'])}")
