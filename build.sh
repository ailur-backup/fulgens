#!/bin/sh

clear

fancy() {
    width="$(tput cols)"
    # Create a string of spaces based on the width
    spaces=$(printf '%*s' "$width" '' | tr ' ' ' ')

    # Print the formatted output
    printf "%b%s  %s  %s%s\n\033[0m" "$1" "$spaces" "$2" "$(printf '%*s' "$((width - ${#2} - 4))" '' | tr ' ' ' ')" "$spaces"
}

fancy "\033[1;106m" "Welcome to fulgens! Starting build..."

sleep 1

path=$(realpath "$(dirname "$0")") || exit 1
searchDir="$path/services-src"
find -L "$searchDir" -type f -name "build.sh" | while read -r buildScript; do
    clear
    buildDir=$(dirname "$buildScript")
    fancy "\033[1;104m" "Starting build of $(basename "$buildDir")..."
    (cd "$buildDir" && ./build.sh) || {
        printf "\033[1;31mError: %s failed.\033[0m\n" "$buildScript"
        exit 1
    }
done
clear
fancy "\033[1;105m" "Building Fulgens..."
go build --ldflags "-s -w" -o "$path/fulgens" || exit 1
clear
fancy "\033[1;102m" "Fulgens has been built successfully!"