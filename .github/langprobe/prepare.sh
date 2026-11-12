#!/usr/bin/env bash
# TEST ONLY. Builds a small project for one scenario in ./probe.
# Probe code only appends one line to /tmp/socket-probe-marker. It records whether
# token variables exist in the environment, never their values.
set -euo pipefail
scenario="$1"
mkdir probe && cd probe

case "$scenario" in
  rust)
    cat > Cargo.toml <<'T'
[workspace]
members = ["app", "probe_macro"]
resolver = "2"
T
    mkdir -p app/src probe_macro/src
    cat > app/Cargo.toml <<'T'
[package]
name = "probe-app"
version = "0.1.0"
edition = "2021"
build = "build.rs"

[dependencies]
smallvec = "=1.6.0"
regex = "=1.5.4"
probe_macro = { path = "../probe_macro" }
T
    cat > app/build.rs <<'T'
use std::{env, fs::OpenOptions, io::Write};
fn main() {
    let mut f = OpenOptions::new().create(true).append(true).open("/tmp/socket-probe-marker").unwrap();
    writeln!(f, "ran=rust-build.rs socket_key={} socket_cli_token={} gh_token={}",
        env::var_os("SOCKET_SECURITY_API_KEY").is_some(),
        env::var_os("SOCKET_CLI_API_TOKEN").is_some(),
        env::var_os("GH_API_TOKEN").is_some()).unwrap();
}
T
    cat > app/src/main.rs <<'T'
use smallvec::SmallVec;
probe_macro::probe!();
fn main() {
    let mut v: SmallVec<[u8; 4]> = SmallVec::new();
    v.insert_many(0, std::env::args().map(|a| a.len() as u8));
    let re = regex::Regex::new(&std::env::args().nth(1).unwrap_or_default()).unwrap();
    println!("{:?} {}", v, re.is_match("x"));
}
T
    cat > probe_macro/Cargo.toml <<'T'
[package]
name = "probe_macro"
version = "0.1.0"
edition = "2021"

[lib]
proc-macro = true
T
    cat > probe_macro/src/lib.rs <<'T'
use proc_macro::TokenStream;
use std::{env, fs::OpenOptions, io::Write};
#[proc_macro]
pub fn probe(_input: TokenStream) -> TokenStream {
    let mut f = OpenOptions::new().create(true).append(true).open("/tmp/socket-probe-marker").unwrap();
    writeln!(f, "ran=rust-proc-macro socket_key={} socket_cli_token={} gh_token={}",
        env::var_os("SOCKET_SECURITY_API_KEY").is_some(),
        env::var_os("SOCKET_CLI_API_TOKEN").is_some(),
        env::var_os("GH_API_TOKEN").is_some()).unwrap();
    TokenStream::new()
}
T
    cargo --version
    cargo generate-lockfile -q ;;
  go)
    cat > go.mod <<'T'
module example.com/probe

go 1.21

require golang.org/x/text v0.3.7
T
    cat > main.go <<'T'
package main

import (
	"fmt"

	"golang.org/x/text/language"
)

//go:generate sh -c "echo ran=go-generate >> /tmp/socket-probe-marker"

func init() {
	fmt.Println("init")
}

func main() {
	tags, _, _ := language.ParseAcceptLanguage("en")
	fmt.Println(tags)
}
T
    cat > main_test.go <<'T'
package main

import (
	"os"
	"testing"
)

func TestProbe(t *testing.T) {
	f, _ := os.OpenFile("/tmp/socket-probe-marker", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	f.WriteString("ran=go-test\n")
	f.Close()
}
T
    go version
    go mod tidy ;;
  poetry)
    cat > probe_backend.py <<'T'
import os
with open("/tmp/socket-probe-marker", "a") as marker:
    marker.write("ran=python-build-backend socket_key=%s socket_cli_token=%s gh_token=%s\n" % (
        "SOCKET_SECURITY_API_KEY" in os.environ,
        "SOCKET_CLI_API_TOKEN" in os.environ,
        "GH_API_TOKEN" in os.environ))
from poetry.core.masonry.api import *
T
    cat > pyproject.toml <<'T'
[tool.poetry]
name = "probe-app"
version = "0.1.0"
description = "probe"
authors = ["probe <probe@example.com>"]
package-mode = false

[tool.poetry.dependencies]
python = "^3.11"
pyyaml = "5.3.1"
requests = "2.19.1"

[build-system]
requires = ["poetry-core"]
build-backend = "probe_backend"
backend-path = ["."]
T
    printf 'import sys\nimport yaml\nimport requests\n\nprint(yaml.load(sys.argv[1], Loader=yaml.Loader), requests.get(sys.argv[2]))\n' > app.py
    python -m pip install -q poetry
    poetry lock -q || poetry lock ;;
  *) echo "unknown scenario $scenario"; exit 2 ;;
esac

# Anything written while preparing does not count.
rm -f /tmp/socket-probe-marker
find . -maxdepth 2 -not -path './target*' | sort
