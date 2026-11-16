#!/bin/bash

# Regenerates internal/api from the pinned spec.
#
# Unlike an ecosystem with a build step, a Go module is consumed as source, so
# the generated file is COMMITTED. Run this after scripts/download-spec.sh and
# commit the spec change and the regenerated client together.
#
# The generator is pinned here rather than in go.mod: a `tool` directive would
# put the whole codegen dependency tree into the module graph of every consumer.

set -euo pipefail

cd "$(dirname "$0")/.."

GENERATOR="${GENERATOR:-github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0}"

go run "$GENERATOR" -config oapi-codegen.yaml spec/openapi.yaml

# Asn.Asn stays an int, as it was through spec 2026.11.14. The spec types it
# int64 from 2026.11.15, and Asn is a public alias of this struct, so int64
# would change a public field's type, a new major. Go's int is 64 bits on every
# 64-bit platform; on 386 and 32-bit arm an AS past 2^31 - 1 still fails to decode.
sed -i 's/^\tAsn int64 `json:"asn"`$/\tAsn int `json:"asn"`/' internal/api/api_gen.go
if ! grep -qP '^\tAsn int `json:"asn"`$' internal/api/api_gen.go ; then
    echo "could not keep Asn.Asn an int: the generated struct changed shape" >&2
    exit 1
fi
gofmt -l internal/api
echo "internal/api/api_gen.go <- spec/openapi.yaml (${GENERATOR##*@})"
