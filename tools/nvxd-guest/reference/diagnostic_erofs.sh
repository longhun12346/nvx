#!/bin/sh
# Shared by diagnostic builders. The runtime inputs are never modified.
# Call after input/output/stage are set; $1 is the original EROFS layer.
diagnostic_erofs_extract() {
    distro_input=$(realpath "$1")
    distro_output="${output}.erofs"
    [ "$distro_input" != "$distro_output" ] || return 2
    [ ! -e "$output" ] && [ ! -e "$distro_output" ] || {
        echo "diagnostic outputs must be new files" >&2
        return 2
    }
    fsck.erofs --extract="$stage/root" "$distro_input"
}

diagnostic_erofs_pack() {
    mkfs.erofs --quiet --all-root -T 0 -z lz4hc "$distro_output" "$stage/root"
    cp "$input" "$output"
    sha256sum "$input" "$distro_input" "$output" "$distro_output"
}
