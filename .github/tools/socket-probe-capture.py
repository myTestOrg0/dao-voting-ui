"""PROTOTYPE. mitmproxy addon for the Socket probe workflow.

Writes one line per request (method, host, path, body sizes) and stores the
request bodies, so that it can be checked what leaves the runner during a scan.
Headers and query values are never written: they carry the Socket API key.
"""

import json
import os
import pathlib

OUT = pathlib.Path(os.environ["CAPTURE_DIR"])
BODIES = OUT / "bodies"
BODIES.mkdir(parents=True, exist_ok=True)
counter = 0


def response(flow):
    global counter
    counter += 1
    request = flow.request
    body = request.raw_content or b""
    record = {
        "n": counter,
        "method": request.method,
        "host": request.pretty_host,
        "path": request.path.split("?", 1)[0],
        "query_keys": sorted(request.query.keys()),
        "request_type": request.headers.get("content-type", ""),
        "request_bytes": len(body),
        "status": flow.response.status_code if flow.response else None,
        "response_bytes": len(flow.response.raw_content or b"") if flow.response else 0,
    }
    if body:
        (BODIES / f"{counter:04d}.bin").write_bytes(body)
    with (OUT / "requests.jsonl").open("a") as log:
        log.write(json.dumps(record) + "\n")
