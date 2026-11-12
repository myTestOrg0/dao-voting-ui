import sys

import requests
import yaml
from flask import Flask
import jinja2  # imported, never used

app = Flask(__name__)


@app.route("/")
def index():
    config = yaml.load(open(sys.argv[1]), Loader=yaml.Loader)
    response = requests.get(config["url"], timeout=5)
    return response.text


if __name__ == "__main__":
    app.run()
