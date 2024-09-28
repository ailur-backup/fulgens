#!/bin/sh

path=$(realpath "$(dirname "$0")") || exit 1
rm -rf "$path/../../services/storage.fgs" || exit 1
go build -o "$path/../../services/storage.fgs" --buildmode=plugin -ldflags "-s -w" || exit 1
