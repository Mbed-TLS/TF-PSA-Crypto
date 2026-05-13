#!/usr/bin/env sh

set -eu

link_target="$1"
link_path="$2"

if [ ! -L "$link_path" ]; then
    ln -s "$link_target" "$link_path"
fi
