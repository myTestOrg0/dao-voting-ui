"""Uses requests, flask, pyjwt and the safe YAML loader.

sqlalchemy is imported and never used. aiohttp, cryptography, pillow, protobuf,
lxml, paramiko and gunicorn are installed and never imported.
"""
import sys

import jwt
import requests
import sqlalchemy  # noqa: F401
import yaml
from flask import Flask, request

app = Flask(__name__)
CONFIG = yaml.safe_load(open(sys.argv[1]))


@app.route("/")
def index():
    claims = jwt.decode(request.headers["Authorization"], CONFIG["key"], algorithms=["HS256"])
    return requests.get(CONFIG["url"], params=claims, timeout=5).text


if __name__ == "__main__":
    app.run()
