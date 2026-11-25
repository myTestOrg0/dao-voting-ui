"""Scope lidofinance/vex statements to one repository before Trivy reads them.

Runs on the copy Trivy downloaded (`trivy vex repo download`), in place:
    python3 vex_scope_filter.py <cache>/vex/repositories/internal/0.1 <owner/repo>

A not_affected/fixed statement stays only if <owner/repo> is in its
whitelist_repositories and whitelist_expires (YYYY-MM-DD, inclusive) has not passed.
Other statuses stay. Documents left without statements are removed from index.json.
Any malformed input raises, so the scan step fails instead of scanning unfiltered data.
"""

import json
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path

SUPPRESSING = {"not_affected", "fixed"}


def allowed(statement, repository, today):
    if statement.get("status") not in SUPPRESSING:
        return True
    repositories = statement.get("whitelist_repositories")
    if not isinstance(repositories, list):
        return False
    return repository in repositories and date.fromisoformat(statement["whitelist_expires"]) >= today


def main(root, repository):
    root = Path(root)
    today = date.fromisoformat(os.environ.get("VEX_TODAY") or datetime.now(timezone.utc).date().isoformat())
    index_path = root / "index.json"
    index = json.loads(index_path.read_text())
    kept_entries = []
    for entry in index["packages"]:
        path = (root / entry["location"]).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError(f"location outside the repository: {entry['location']}")
        document = json.loads(path.read_text())
        statements = document["statements"]
        document["statements"] = [s for s in statements if allowed(s, repository, today)]
        for s in statements:
            verdict = "keep" if s in document["statements"] else "drop"
            print(f"{verdict}  {s['vulnerability']['name']}  {entry['id']}  status={s.get('status')}"
                  f"  repos={s.get('whitelist_repositories')}  expires={s.get('whitelist_expires')}")
        if document["statements"]:
            path.write_text(json.dumps(document))
            kept_entries.append(entry)
        else:
            path.unlink()
    total = len(index["packages"])
    index["packages"] = kept_entries
    index_path.write_text(json.dumps(index))
    print(f"repository={repository} today={today}: {len(kept_entries)} of {total} documents kept")


if __name__ == "__main__":
    main(*sys.argv[1:])
