#!/usr/bin/env bash
# TEST ONLY. Builds a small Python project for one scenario in ./pyprobe.
# Probe files only append one line to /tmp/socket-py-probe-marker. They record
# whether token variables exist in the environment, never their values.
set -euo pipefail
scenario="$1"
mkdir pyprobe && cd pyprobe

probe() { # probe <label> : python lines that write the marker
  cat <<PY
import os, sys
with open("/tmp/socket-py-probe-marker", "a") as marker:
    marker.write("ran=$1 args=%s socket_key=%s socket_cli_token=%s gh_token=%s\n" % (
        "+".join(sys.argv[1:2]),
        "SOCKET_SECURITY_API_KEY" in os.environ,
        "SOCKET_CLI_API_TOKEN" in os.environ,
        "GH_API_TOKEN" in os.environ))
PY
}

cat > app.py <<'PY'
import sys
import yaml
import docopt


def main(text):
    docopt.docopt("Usage: app <text>")
    return yaml.load(text, Loader=yaml.Loader)


if __name__ == "__main__":
    print(main(sys.argv[1]))
PY

deps='pyyaml==5.3.1
docopt==0.6.2'

project_setup_py() {
  { probe project-setup.py
    echo 'from setuptools import setup'
    echo 'setup(name="pyprobe-app", version="0.1.0", py_modules=["app"], install_requires=["pyyaml==5.3.1", "docopt==0.6.2"])'
  } > setup.py
}

case "$scenario" in
  pypi|pypi-no-downloads)
    echo "$deps" > requirements.txt ;;
  path-dep)
    mkdir probe_pkg
    { probe path-dep-setup.py
      echo 'from setuptools import setup'
      echo 'setup(name="local-probe", version="1.0.0", py_modules=["local_probe"])'
    } > probe_pkg/setup.py
    echo 'VALUE = 1' > probe_pkg/local_probe.py
    echo 'import local_probe' >> app.py
    printf '%s\n./probe_pkg\n' "$deps" > requirements.txt ;;
  git-dep)
    echo 'import socket_py_probe' >> app.py
    printf '%s\nsocket-py-probe @ git+https://github.com/myTestOrg0/dao-voting-ui@353ab2c13f4a865549c6662d3c72da6396a0a2b1\n' "$deps" > requirements.txt ;;
  setup-py)
    project_setup_py ;;
  editable)
    project_setup_py
    printf '%s\n-e .\n' "$deps" > requirements.txt ;;
  backend-uvlock)
    { probe project-build-backend
      echo 'from setuptools.build_meta import *'
    } > probe_backend.py
    cat > pyproject.toml <<'TOML'
[project]
name = "pyprobe-app"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["pyyaml==5.3.1", "docopt==0.6.2"]

[build-system]
requires = ["setuptools"]
build-backend = "probe_backend"
backend-path = ["."]
TOML
    uv lock -q ;;
  sdist-only)
    # Vulnerable releases that were published without any wheel.
    printf 'import Crypto\nimport ansible\nimport django\n' >> app.py
    printf '%s\npycrypto==2.6.1\nansible==2.9.9\nDjango==1.4.22\n' "$deps" > requirements.txt ;;
  index-line)
    printf -- '--index-url https://test.pypi.org/simple/\n%s\n' "$deps" > requirements.txt ;;
  uv-config)
    echo "$deps" > requirements.txt
    printf '[[index]]\nurl = "https://test.pypi.org/simple/"\ndefault = true\n' > uv.toml
    printf '[global]\nindex-url = https://test.pypi.org/simple/\n' > pip.conf ;;
  wheel-control)
    echo 'requests==2.19.1' > requirements.txt ;;
  uv-toml-index)
    echo 'requests==2.19.1' > requirements.txt
    printf '[[index]]\nurl = "https://example.invalid/simple/"\ndefault = true\n' > uv.toml ;;
  pyproject-uv-index)
    echo 'requests==2.19.1' > requirements.txt
    printf '[project]\nname = "pyprobe-app"\nversion = "0.1.0"\n\n[[tool.uv.index]]\nurl = "https://example.invalid/simple/"\ndefault = true\n' > pyproject.toml ;;
  req-index-line)
    printf -- '--index-url https://example.invalid/simple/\nrequests==2.19.1\n' > requirements.txt ;;
  *) echo "unknown scenario $scenario"; exit 2 ;;
esac

# Anything written while preparing does not count.
rm -f /tmp/socket-py-probe-marker
ls -la
