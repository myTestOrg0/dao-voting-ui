"""Evaluate server-resolved Socket actions and render a read-only Actions summary."""

import base64
import html
import json
import os
import re
from collections import Counter
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


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


def get_api(org, path):
    token = os.environ.get("SOCKET_SECURITY_API_KEY", "")
    if not token:
        raise ValueError("Socket API secret is unavailable")
    auth = base64.b64encode((token + ":").encode()).decode()
    request = Request(
        f"https://api.socket.dev/v0/orgs/{quote(org, safe='')}/{path}",
        headers={"Authorization": "Basic " + auth},
    )
    try:
        with urlopen(request, timeout=180) as response:
            return response.read().decode()
    except HTTPError as error:
        raise ValueError(f"Socket report request failed: HTTP {error.code}") from None
    except (URLError, TimeoutError):
        raise ValueError("Socket report request failed: network error or timeout") from None


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


def server_exit_code(rows):
    """Unknown actions fail verification; only resolved Block findings fail policy."""
    if any(f["action"] == "unknown" for f in rows):
        return 2
    return 1 if any(f["action"] == "error" for f in rows) else 0


def advisory_exit_code(rows):
    """A red, optional check for unresolved vulnerabilities and actionable alerts."""
    if any(f['action'] == 'unknown' for f in rows):
        return 2
    return int(any(f['action'] in ('error', 'warn') or
                   (f.get('vulnerability') and f['action'] != 'ignore') for f in rows))


def displayed(finding):
    return finding['action'] in ('error', 'warn', 'unknown') or (
        os.environ.get('SOCKET_FAIL_ON_FINDINGS') == 'true' and finding.get('vulnerability') and finding['action'] != 'ignore')


def advisory_label(finding):
    ghsa = finding["ghsa"]
    if re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", ghsa):
        return f"[{md(finding['id'])}](https://github.com/advisories/{ghsa})"
    return md(finding["id"])


def table(rows):
    lines = ["| Package | Version | Advisory / alert | Severity | Action | Upstream fix |", "|---|---|---|---|---|---|"]
    for f in rows:
        action = "Block" if f["action"] == "error" else f["action"].capitalize()
        lines.append(f"| {md(f['package'])} | {md(f['version'])} | {advisory_label(f)} | {md(f['severity'])} | {md(action)} | {md(f['fixed_version'])} |")
    return "\n".join(lines)


def render_summary(result, rows, manifests, component_count, org, sha, report_url="", file_count=None):
    data = result["data"]
    counts = Counter(f["action"] for f in rows)
    cves = Counter(f["severity"] for f in rows if f["vulnerability"])
    visible = [f for f in rows if displayed(f)]
    code = advisory_exit_code(rows) if os.environ.get("SOCKET_FAIL_ON_FINDINGS") == "true" else server_exit_code(rows)
    verdict = {0: "Server policy passed", 1: "Server policy failed", 2: "Server policy verification incomplete"}[code]
    if os.environ.get('SOCKET_FAIL_ON_FINDINGS') == 'true':
        verdict = {0: 'No unresolved findings', 1: 'Findings detected — optional failed check', 2: 'Verification incomplete'}[code]
    scan_id = data.get("id") or data.get("scanId")
    lines = ["## Socket dependency scan", "", f"**{verdict}** · {md(os.environ.get('SOCKET_SCAN_MODE', 'manifest snapshot'))} · Socket CLI 1.13.1", "", f"Organization: {md(org)} · commit: `{sha}` · scan: `{scan_id}`", ""]
    if os.environ.get('SOCKET_FAIL_ON_FINDINGS') == 'true':
        lines += ['This check fails for unresolved vulnerabilities, including Monitor. Merge remains allowed only while this check is not required by GitHub branch rules.', '']
    if report_url:
        lines += [f"[Open Socket report]({report_url})", ""]
    lines += ["| Components | Block | Warn | Monitor | Ignore | Unknown action |", "|---:|---:|---:|---:|---:|---:|", f"| {component_count} | {counts['error']} | {counts['warn']} | {counts['monitor']} | {counts['ignore']} | {counts['unknown']} |", "", "Actions and the final verdict use server-resolved alert.action, including server reachability decisions. Counts are deduplicated by component/version and advisory (or non-CVE alert type).", "", f"**Vulnerability findings:** Critical {cves['critical']} · High {cves['high']} · Medium {cves['medium']} · Low {cves['low']} · Unknown {cves['unknown']}.", "", "Monitor/Ignore findings are retained in the JSON artifact. Passing policy does not mean there are no vulnerabilities.", "", "### Findings needing attention", ""]
    if visible:
        lines += [table(visible[:20]), ""]
        if len(visible) > 20:
            lines += [f"<details><summary>Remaining {len(visible) - 20} findings</summary>", "", table(visible[20:]), "", "</details>", ""]
    else:
        lines += ["No Block/Warn findings were returned for this scan.", ""]
    if counts["unknown"]:
        lines += ["**Attention:** some findings have no recognized policy action; review the full artifact.", ""]
    if file_count is not None:
        lines += [f"CLI auto-discovery selected **{file_count} files**.", ""]
    lines += ["<details><summary>Manifests referenced by scanned components</summary>", ""]
    lines += [f"- {md(path)}" for path in manifests] or ["No manifest paths were returned by the API."]
    lines += ["", "</details>", "", "VEX filtering is not enabled. No PR-comment suppression commands are processed.", "", "Download the `socket-report` artifact for the JSON data and this Markdown report.", ""]
    return "\n".join(lines)


def write_summary(folder, content):
    (folder / "summary.md").write_text(content)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and os.environ.get("SOCKET_EVALUATION_MODE") != "collect":
        with open(summary, "a") as stream:
            stream.write(content)


def print_findings(rows, component_count):
    """Plain logs complement the Markdown summary; never print advisory bodies."""
    counts = Counter(f["action"] for f in rows)
    print(f"Server actions: components={component_count} Block={counts['error']} Warn={counts['warn']} Monitor={counts['monitor']} Ignore={counts['ignore']}")
    print("Package | Version | CVE/GHSA or alert | Severity | Server action | Fix")
    for finding in rows:
        if not displayed(finding):
            continue
        values = [finding[key] for key in ("package", "version", "id", "severity", "action", "fixed_version")]
        safe = [re.sub(r"[\x00-\x1f\x7f]", " ", str(value))[:400] for value in values]
        print("FINDING | " + " | ".join(safe))


def main():
    folder = Path(os.environ["SOCKET_RESULTS_DIR"])
    folder.mkdir(parents=True, exist_ok=True)
    try:
        output = (folder / "cli-output.log").read_text() if (folder / "cli-output.log").exists() else ""
        if (folder / "cli-exit-code").read_text().strip() != "0":
            detail = ""
            try:
                failed = parse_cli_result(output)
                detail = ": " + str(failed.get("message") or "")
                if failed.get("cause"):
                    detail += " / " + str(failed["cause"])
            except ValueError:
                pass
            raise ValueError("Socket scan creation failed; no policy pass can be established" + detail)
        result = parse_cli_result(output)
        data = result.get("data") or {}
        if not result["ok"] or not data.get("id"):
            raise ValueError("Scan/report did not complete; inspect the scan step logs")
        scan_id = data["id"]
        if not re.fullmatch(r"[a-zA-Z0-9-]+", scan_id):
            raise ValueError("Invalid scan ID in CLI output")
        org = os.environ["SOCKET_ORG"]
        raw = get_api(org, f"full-scans/{scan_id}?include_license_details=true")
        artifacts = [json.loads(line) for line in raw.splitlines() if line.strip()]
        rows, manifests, component_count = collect_findings(artifacts)
        # Do not let deduplication hide an unknown action behind a known one.
        unknown_actions = any(
            alert.get("action") not in ("error", "block", "warn", "monitor", "ignore")
            for artifact in artifacts if isinstance(artifact, dict)
            for alert in (artifact.get("alerts") or [])
        )
        if not component_count:
            raise ValueError("No named components in scan response; coverage is unverified")
        report_url = ""
        try:
            metadata = json.loads(get_api(org, f"full-scans/{scan_id}/metadata"))
            candidate = metadata.get("html_report_url", "")
            parsed = urlparse(candidate)
            if parsed.scheme == "https" and parsed.hostname == "socket.dev":
                report_url = candidate
        except (ValueError, TypeError):
            pass  # Optional navigation metadata must not hide the findings.
        match = re.search(r"Found (\d+) files? to include in scan", output)
        content = render_summary(result, rows, manifests, component_count, org, os.environ["SCAN_SHA"], report_url, int(match[1]) if match else None)
        policy_code = server_exit_code(rows)
        code = 2 if unknown_actions else (advisory_exit_code(rows) if os.environ.get("SOCKET_FAIL_ON_FINDINGS") == "true" else policy_code)
        if unknown_actions:
            content = content.replace("**Server policy passed**", "**Server policy verification incomplete**").replace("**Server policy failed**", "**Server policy verification incomplete**")
            content += "\n**Verification incomplete:** the raw scan contains an unrecognized policy action.\n"
        decision = {"source": "server alert.action", "scanId": scan_id, "components": component_count,
                    "healthy": code == 0, "verification_complete": code != 2,
                    "exit_code": code, "server_policy_exit_code": policy_code, "actions": dict(Counter(f["action"] for f in rows)),
                    "creation": result}
        (folder / "report.json").write_text(json.dumps(decision, indent=2))
        (folder / "findings.json").write_text(json.dumps(rows, indent=2))
        (folder / "scan-artifacts.json").write_text(json.dumps(artifacts))
        write_summary(folder, content)
        print_findings(rows, component_count)
        print(f"Socket summary: {component_count} components, {len(rows)} grouped findings; scan {scan_id}")
        if os.environ.get('SOCKET_EVALUATION_MODE') == 'collect' and code != 2:
            return 0  # Collection completed; VEX evaluates findings in the following step.
        if code:
            print("::error::Socket findings detected or verification incomplete; see Actions Summary. Merge depends on required-check settings.")
        return code
    except (ValueError, OSError, KeyError, TypeError) as error:
        # Never print raw API bodies, credentials, or the captured CLI output.
        message = str(error)
        token = os.environ.get("SOCKET_SECURITY_API_KEY")
        if token:
            message = message.replace(token, "[redacted]").replace(base64.b64encode((token + ":").encode()).decode(), "[redacted]")
        (folder / "failure.json").write_text(json.dumps({"status": "verification_incomplete", "reason": message[:2000]}))
        write_summary(folder, "## Socket dependency scan\n\n**Report unavailable — verification incomplete.**\n\n" + md(message) + "\n\nInspect the scan step logs.\n")
        print("Verification incomplete: " + re.sub(r"[\x00-\x1f\x7f]", " ", message)[:2000])
        print("::error::Socket summary could not be completed; inspect Actions Summary")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
