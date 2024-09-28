#!/bin/sh

path=$(realpath "$(dirname "$0")") || exit 1
resourceDir="$path/../../resources/00000000-0000-0000-0000-000000000004"
rm -rf "$resourceDir" || exit 1
rm -rf "$path/../../services/auth.fgs" || exit 1
cd "$path" || exit 1
go build -o "$path/../../services/auth.fgs" --buildmode=plugin -ldflags "-s -w" || exit 1
mkdir -p "$resourceDir/static/wasm" || exit 1
cd "$path/resources/wasm/login" || exit 1
GOOS=js GOARCH=wasm go build -o "$resourceDir/static/wasm/login.wasm" -ldflags "-s -w" || exit 1
cd "$path/resources/wasm/signup" || exit 1
GOOS=js GOARCH=wasm go build -o "$resourceDir/static/wasm/signup.wasm" -ldflags "-s -w" || exit 1
cd "$path/resources/wasm/authorize" || exit 1
GOOS=js GOARCH=wasm go build -o "$resourceDir/static/wasm/authorize.wasm" -ldflags "-s -w" || exit 1
cd "$path/resources/wasm/dashboard" || exit 1
GOOS=js GOARCH=wasm go build -o "$resourceDir/static/wasm/dashboard.wasm" -ldflags "-s -w" || exit 1
cd "$path/resources/wasm/testApp" || exit 1
GOOS=js GOARCH=wasm go build -o "$resourceDir/static/wasm/testApp.wasm" -ldflags "-s -w" || exit 1
cd "$path/resources/wasm/clientKeyShare" || exit 1
GOOS=js GOARCH=wasm go build -o "$resourceDir/static/wasm/clientKeyShare.wasm" -ldflags "-s -w" || exit 1
cp -r "$path/resources/static" "$resourceDir/" || exit 1
cp -r "$path/resources/templates" "$resourceDir/" || exit 1