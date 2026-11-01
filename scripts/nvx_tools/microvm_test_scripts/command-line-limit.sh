set -eu
fail() {
    code="$1"
    echo "NVX-COMMAND-LINE-LIMIT-FAIL code=$code"
    nvx-exit "$code"
    exit "$code"
}

# The host compares the whole command line with the one it expects.
printf 'NVX-COMMAND-LINE: %s\n' "$(cat /proc/cmdline)"
# OpenVMM appends the network bootstrap last, and the guest's init installs
# the IPv6 default route that its last token, virtnet_gw6=, names.
grep -q '^00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd00000000000000000000000a000001 ' \
    /proc/net/ipv6_route || fail 20
echo NVX-COMMAND-LINE-LIMIT-OK
nvx-exit 0
