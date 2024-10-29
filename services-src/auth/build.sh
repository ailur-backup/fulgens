#!/bin/sh

path=$(realpath "$(dirname "$0")") || exit 1
resourceDir="$path/../../resources/00000000-0000-0000-0000-000000000004"
rm -rf "$resourceDir" || exit 1
rm -rf "$path/../../services/auth.fgs" || exit 1
cd "$path" || exit 1
printf "\033[1;35mBuilding auth.fgs...\033[0m\n"
go build -o "$path/../../services/auth.fgs" --buildmode=plugin -ldflags "-s -w" || exit 1
mkdir -p "$resourceDir/static/wasm" || exit 1
find -L "$path/resources/wasm" -type f -name "main.go" | while read -r mainGo; do
    buildDir=$(dirname "$mainGo")
    baseName=$(basename "$buildDir")
    printf "\033[1;34m\033[1;33mBuilding WASM object %s...\033[0m\n" "$baseName"
    (cd "$buildDir" && GOOS=js GOARCH=wasm go build -o "$resourceDir/static/wasm/$(basename "$buildDir").wasm" -ldflags "-s -w") || {
        printf "\033[1;31mError: %s failed.\033[0m\n" "$mainGo"
        exit 1
    }
done
printf "\033[1;34mCopying static files...\033[0m\n"
cp -r "$path/resources/static" "$resourceDir/" || exit 1
cp -r "$path/resources/templates" "$resourceDir/" || exit 1
printf "\033[1;36mauth.fgs has been built successfully!\033[0m\n"