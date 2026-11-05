"""Read a POC scan and policy without modifying Socket configuration."""

import base64
import json
import os
from collections import Counter
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def get_api(path):
    token = os.environ["SOCKET_SECURITY_API_KEY"]
    credentials = base64.b64encode((token + ":").encode()).decode()
    request = Request(
        "https://api.socket.dev/v0/" + path,
        headers={"Authorization": "Basic " + credentials},
    )
    try:
        with urlopen(request, timeout=180) as response:
            return response.read().decode()
    except HTTPError as error:
        raise SystemExit(f"Socket diagnostics request failed: HTTP {error.code}") from None


org = "lido-labs"
scan_id = os.environ["SOCKET_SCAN_ID"]
policy = json.loads(get_api(f"orgs/{org}/settings/security-policy"))
rules = policy.get("securityPolicyRules")
if not isinstance(rules, dict):
    raise SystemExit("Cannot inspect securityPolicyRules; response fields: " + str(list(policy)))

print("SCAN_ID", scan_id)
print("POLICY_ACTION_COUNTS", json.dumps(Counter(rule.get("action", "unknown") for rule in rules.values()), sort_keys=True))
for alert_type in ("malware", "criticalCVE", "highCVE", "mediumCVE", "lowCVE", "licensePolicyViolation"):
    print("POLICY_RULE", alert_type, json.dumps(rules.get(alert_type), sort_keys=True))

raw = get_api(f"orgs/{org}/full-scans/{scan_id}?include_license_details=true")
artifacts = [json.loads(line) for line in raw.splitlines() if line.strip()]
print("RESPONSE_RECORDS", len(artifacts))
print("RECORD_TYPE_COUNTS", json.dumps(Counter(a.get("type", "unknown") for a in artifacts), sort_keys=True))
print("RECORD_WITH_PACKAGE_NAME", sum(bool(a.get("name")) for a in artifacts))
print("FIRST_RECORD_FIELDS", json.dumps(list(artifacts[0]) if artifacts else []))

alert_types = Counter()
actions = Counter()
cve_packages = set()
selected = {"axios", "postcss", "ws", "next", "lodash"}
for artifact in artifacts:
    alerts = artifact.get("alerts") or []
    for alert in alerts:
        alert_type = alert.get("type", "unknown")
        alert_types[alert_type] += 1
        actions[rules.get(alert_type, {}).get("action", "unmapped")] += 1
        if "cve" in alert_type.lower():
            cve_packages.add((artifact.get("name", "unknown"), artifact.get("version", "unknown")))
    if artifact.get("name") in selected:
        print("SELECTED_PACKAGE", json.dumps({"name": artifact.get("name"), "version": artifact.get("version"), "type": artifact.get("type"), "alertCount": len(alerts), "alertTypeCounts": Counter(a.get("type", "unknown") for a in alerts), "sampleAlerts": alerts[:3]}, sort_keys=True))

print("RAW_ALERT_TYPE_COUNTS", json.dumps(alert_types, sort_keys=True))
print("RAW_ALERT_ACTION_COUNTS", json.dumps(actions, sort_keys=True))
print("PACKAGES_WITH_CVE_ALERTS", len(cve_packages))
print("CLI_BLOCKING_ALERTS_BY_TYPE_POLICY", actions.get("error", 0))
