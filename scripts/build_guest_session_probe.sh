#!/bin/sh
# Build a diagnostic-only initrd from an existing runtime. Does not replace it.
set -eu
if [ "$#" -ne 2 ]; then
    echo "usage: $0 runtime.cpio.gz probe.cpio.gz" >&2
    exit 2
fi
input=$(realpath "$1")
output=$(realpath -m "$2")
[ "$input" != "$output" ] || exit 2
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
stage=$(mktemp -d /tmp/nvx-session-probe.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
cc -std=gnu11 -static -O2 -Wall -Wextra -Werror \
    "$repo/scripts/guest_session_probe.c" -o "$stage/p8-session-probe"
mkdir -p "$stage/usr/sbin"
cc -std=gnu11 -static -O2 -Wall -Wextra -Werror \
    "$repo/guest/common/nvx-managed-agent.c" -o "$stage/usr/sbin/nvx-managed-agent"
cat >"$stage/p8-probe-boot" <<'EOF'
#!/bin/sh
status=0
/p8-session-probe --scheduler || status=$?
exec /sbin/nvx-exit "$status"
EOF
chmod 0755 "$stage/p8-probe-boot"
cp "$input" "$output"
(
    cd "$stage"
    printf '%s\n' p8-session-probe p8-probe-boot usr usr/sbin usr/sbin/nvx-managed-agent |
        cpio -o -H newc --quiet --owner=0:0 | gzip -n
) >>"$output"
sha256sum "$input" "$output" "$repo/scripts/guest_session_probe.c" \
    "$repo/guest/common/nvx-guest-session.h" "$repo/guest/common/nvx-managed-agent.c"
