#!/usr/bin/env bash
# TEST ONLY. Builds a small project with known-vulnerable dependencies in ./probe.
# Some vulnerable functions are called by the code, some packages are only
# imported, some are not used at all.
set -euo pipefail
scenario="$1"
mkdir probe && cd probe

case "$scenario" in
  python)
    cat > requirements.txt <<'T'
requests==2.19.1
urllib3==1.23
idna==2.7
certifi==2018.4.16
chardet==3.0.4
pyyaml==5.3.1
jinja2==2.10
markupsafe==1.0
flask==0.12.2
werkzeug==0.14.1
itsdangerous==0.24
click==6.7
cryptography==3.2
cffi==1.14.3
pycparser==2.20
six==1.15.0
pillow==8.0.0
aiohttp==3.7.3
multidict==5.0.2
yarl==1.6.3
async-timeout==3.0.1
attrs==20.3.0
typing-extensions==3.7.4.3
T
    cat > app.py <<'T'
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
T
    ;;
  go)
    cat > go.mod <<'T'
module example.com/probe

go 1.21

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gin-gonic/gin v1.6.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/text v0.3.7
	gopkg.in/yaml.v2 v2.2.2
)
T
    cat > main.go <<'T'
package main

import (
	"fmt"
	"os"

	_ "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v2"
)

func main() {
	var config map[string]string
	data, _ := os.ReadFile(os.Args[1])
	_ = yaml.Unmarshal(data, &config)
	tags, _, _ := language.ParseAcceptLanguage(config["lang"])
	hash, _ := bcrypt.GenerateFromPassword([]byte(config["password"]), 10)
	fmt.Println(tags, len(hash))
	router := gin.Default()
	router.GET("/", func(c *gin.Context) { c.String(200, "ok") })
	_ = router.Run()
}
T
    go version
    go mod tidy ;;
  *) echo "unknown scenario $scenario"; exit 2 ;;
esac
ls -la
