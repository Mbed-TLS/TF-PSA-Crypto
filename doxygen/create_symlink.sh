#!/usr/bin/env sh

set -eu

link_target="$1"
link_path="$2"

if [ ! -e "$link_path" ]; then
    ln -sf "$link_target" "$link_path"
fi
