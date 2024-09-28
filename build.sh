#!/bin/sh
path=$(realpath "$(dirname "$0")") || exit 1
search_dir="$path/services-src"
find "$search_dir" -type f -name "build.sh" | while read -r build_script; do
    echo "Running $build_script..."
    build_dir=$(dirname "$build_script")
    (cd "$build_dir" && ./build.sh) || {
        echo "Error: $build_script failed."
        exit 1
    }
done
go build --ldflags "-s -w" -o "$path/fulgens" || exit 1
echo "Fulgens has been built successfully."
