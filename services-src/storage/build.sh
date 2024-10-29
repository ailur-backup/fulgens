#!/bin/sh

path=$(realpath "$(dirname "$0")") || exit 1
rm -rf "$path/../../services/storage.fgs" || exit 1
printf "\033[1;35mBuilding storage.fgs...\033[0m\n"
go build -o "$path/../../services/storage.fgs" --buildmode=plugin -ldflags "-s -w" || exit 1
printf "\033[1;36mstorage.fgs has been built successfully!\033[0m\n"