#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$script_dir/../tools/socket-cli"
python3 - "$source_dir/dependencies.lock" <<'PYVERIFY'
"""Verify reviewed CLI lock bytes before npm installs any package."""
import hashlib
import json
import sys
from pathlib import Path

LOCK_SHA256 = "8e08f1210ed72a39f14ab565083a228591e50ed9e4716aa5e4d2c3f1fa46c023"
SOCKET_SRI = "sha512-du881tyG17a2TctQEuJDvv5FoAl5zKnSmk2BDmaDbPTLbd64joDeBISppgSS4mhGcL3y3Nvt2pYBLQce6zQ0lg=="

def verify(path):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != LOCK_SHA256:
        raise ValueError("CLI dependency lock SHA-256 mismatch")
    packages = json.loads(raw)["packages"]
    cli = packages["node_modules/socket"]
    if cli["integrity"] != SOCKET_SRI or cli["resolved"] != "https://registry.npmjs.org/socket/-/socket-1.13.1.tgz":
        raise ValueError("Socket tarball pin does not match reviewed SHA-512")
    for name, package in packages.items():
        if name and (not package.get("integrity", "").startswith("sha512-") or not package.get("resolved", "").startswith("https://registry.npmjs.org/")):
            raise ValueError("Dependency lacks an approved URL or SHA-512 integrity")
    return len(packages) - 1

if __name__ == "__main__":
    try:
        print(f"Verified CLI lock SHA-256 {LOCK_SHA256}; {verify(sys.argv[1])} packages with SHA-512 integrity")
    except (ValueError, OSError, KeyError) as error:
        print(f"::error::{error}")
        raise SystemExit(1)

PYVERIFY
if [ "${1:-}" = '--verify-only' ]; then exit 0; fi
install_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/socket-cli-poc"
mkdir -p "$install_dir"
python3 - "$source_dir/dependencies.lock" "$install_dir/package.json" <<'PYMANIFEST'
import json, sys
from pathlib import Path
manifest = json.loads(Path(sys.argv[1]).read_text())["packages"][""]
manifest["private"] = True
Path(sys.argv[2]).write_text(json.dumps(manifest))
PYMANIFEST
cp "$source_dir/dependencies.lock" "$install_dir/package-lock.json"
# npm verifies every downloaded package against the lockfile SRI hash.
# Tool dependency lifecycle scripts do not run.
npm ci --prefix "$install_dir" --ignore-scripts --no-audit --no-fund
"$install_dir/node_modules/.bin/socket" --version
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$install_dir/node_modules/.bin" >> "$GITHUB_PATH"
fi
echo 'Socket CLI 1.13.1 installed from the SHA-512-pinned tarball and SHA-256-pinned dependency lock.'
