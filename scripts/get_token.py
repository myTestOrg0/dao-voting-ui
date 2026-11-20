#!/usr/bin/env python3
"""
Get a GitHub App installation token (ghs_...) to check out one repository.

Same scheme as scripts/get_token.py in lidofinance/infra-mainnet: the App is
installed into the repositories to scan, its private key signs a short-lived
JWT, and the JWT is exchanged for an installation token. The token is masked
in the logs and passed on as the step output "ghs_token".

Differences from that script:

* The token is limited to the one repository being scanned and to read access
  to its contents, instead of everything the installation can reach.
* The installation is looked up by repository, not taken as the first one of
  the App, so the App may be installed into several organizations.
* Only the standard library and the openssl command are used, so the job needs
  no extra Python packages.

When the App is not configured or is not installed into the repository, the
output is empty and the workflow falls back to its own token, which can read
public repositories only.

Environment:
    APP_ID            ID (or client ID) of the GitHub App
    APP_PRIVATE_KEY   private key of the App, PEM
    TARGET_OWNER      owner of the repository to check out
    TARGET_REPO       name of the repository to check out
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import quote

API_URL = os.environ.get("GITHUB_API_URL", "https://api.github.com")


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def make_jwt_token(private_key, app_id):
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    # iat is set a minute back, as GitHub rejects a JWT issued "in the future"
    # when the clocks differ. GitHub accepts a lifetime of at most 10 minutes.
    payload = {"iat": now - 60, "exp": now + 540, "iss": str(app_id)}
    signing_input = b".".join(
        b64url(json.dumps(part, separators=(",", ":")).encode())
        for part in (header, payload)
    )
    # openssl reads the key from a file. The file is private to this user and
    # is removed as soon as the signature is made.
    with tempfile.NamedTemporaryFile("w", suffix=".pem") as key_file:
        key_file.write(private_key)
        key_file.flush()
        signed = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_file.name],
            input=signing_input,
            capture_output=True,
        )
    if signed.returncode != 0:
        fail("openssl could not sign the JWT. Is APP_PRIVATE_KEY a valid PEM private key?")
    return (signing_input + b"." + b64url(signed.stdout)).decode()


def github_api(method, path, jwt_token, body=None):
    """Return (HTTP status, decoded JSON answer)."""
    request = urllib.request.Request(
        API_URL + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "socket-default-branch-scan",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        try:
            answer = json.load(error)
        except ValueError:
            answer = {}
        return error.code, answer if isinstance(answer, dict) else {}
    except (urllib.error.URLError, TimeoutError) as error:
        fail(f"GitHub API is not reachable: {error}")


def get_installation_id(jwt_token, owner, repo):
    """Return the installation of the App in the repository, or None."""
    path = f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/installation"
    status, answer = github_api("GET", path, jwt_token)
    if status == 404:
        return None
    if status != 200:
        fail(f"GitHub answered {status} to the installation lookup: {answer.get('message', '')}")
    return answer["id"]


def get_token(jwt_token, installation_id, repo):
    status, answer = github_api(
        "POST",
        f"/app/installations/{installation_id}/access_tokens",
        jwt_token,
        body={"repositories": [repo], "permissions": {"contents": "read"}},
    )
    if status != 201:
        fail(f"GitHub answered {status} to the token request: {answer.get('message', '')}")
    return answer["token"]


def fail(message):
    print(f"::error::{message}")
    sys.exit(1)


def mask(value):
    if not os.environ.get("GITHUB_ACTIONS"):
        print("error: GITHUB_ACTIONS is not detected", file=sys.stderr)
        sys.exit(1)
    print(f"::add-mask::{value}")


def set_output(key, value):
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        print("Unable to get GITHUB_OUTPUT file name", file=sys.stderr)
        sys.exit(1)
    with open(output_file, "ta") as f:
        f.write(f"{key}={value}\n")


def main():
    private_key = os.environ.get("APP_PRIVATE_KEY", "")
    app_id = os.environ.get("APP_ID", "")
    owner = os.environ["TARGET_OWNER"]
    repo = os.environ["TARGET_REPO"]

    if not private_key or not app_id:
        print(
            "::notice::APP_ID or APP_PRIVATE_KEY is not set. "
            "Only public repositories can be checked out."
        )
        set_output("ghs_token", "")
        return

    # A key stored on one line, with "\n" written out between its lines.
    if "\n" not in private_key.strip() and "\\n" in private_key:
        private_key = private_key.replace("\\n", "\n")
    if not private_key.endswith("\n"):
        private_key += "\n"

    jwt_token = make_jwt_token(private_key, app_id)
    installation_id = get_installation_id(jwt_token, owner, repo)
    if installation_id is None:
        print(
            f"::notice::The GitHub App is not installed into {owner}/{repo}. "
            "It can be checked out only if it is public."
        )
        set_output("ghs_token", "")
        return

    ghs_token = get_token(jwt_token, installation_id, repo)
    mask(ghs_token)
    set_output("ghs_token", ghs_token)
    print(f"Got a read-only token for {owner}/{repo}")


if __name__ == "__main__":
    main()
