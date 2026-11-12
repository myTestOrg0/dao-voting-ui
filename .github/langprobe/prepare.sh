#!/usr/bin/env bash
# TEST ONLY. Builds a small Go project that uses cgo in ./probe.
# The C code holds a probe that would append one line to /tmp/socket-probe-marker
# if the built program were ever started. It records whether token variables
# exist in the environment, never their values.
set -euo pipefail
scenario="$1"
mkdir probe && cd probe

cat > go.mod <<'T'
module example.com/probe

go 1.21

require golang.org/x/text v0.3.7
T

header='#include <stdio.h>'
[ "$scenario" != cgo-broken ] || header='#include "header_that_does_not_exist.h"'

cat > main.go <<T
package main

/*
#cgo CFLAGS: -DPROBE_VALUE=7
$header
#include <stdlib.h>

static int probe_value(void) { return PROBE_VALUE; }

__attribute__((constructor)) static void probe_init(void) {
	FILE *f = fopen("/tmp/socket-probe-marker", "a");
	if (f) {
		fprintf(f, "ran=cgo-constructor socket_key=%d socket_cli_token=%d gh_token=%d\n",
			getenv("SOCKET_SECURITY_API_KEY") != NULL,
			getenv("SOCKET_CLI_API_TOKEN") != NULL,
			getenv("GH_API_TOKEN") != NULL);
		fclose(f);
	}
}
*/
import "C"

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	tags, _, _ := language.ParseAcceptLanguage("en")
	fmt.Println(tags, C.probe_value())
}
T
go version
go env CGO_ENABLED CC
go mod tidy

# Anything written while preparing does not count.
rm -f /tmp/socket-probe-marker
ls -la
