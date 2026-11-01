#!/bin/sh
# Diagnostic overlay: preserve the production agent bytes and start an observer.
set -eu
[ "$#" -eq 2 ] || [ "$#" -eq 3 ] || exit 2
input=$(realpath "$1")
output=$(realpath -m "$2")
[ "$input" != "$output" ] || exit 2
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
stage=$(mktemp -d /tmp/nvx-p8-fault.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
if [ "$#" -eq 3 ]; then
    . "$repo/scripts/diagnostic_erofs.sh"
    diagnostic_erofs_extract "$3"
    mkdir -p "$stage/usr/sbin"
    cp "$stage/root/usr/sbin/nvx-managed-agent" "$stage/usr/sbin/"
else
    (
        cd "$stage"
        gzip -dc "$input" | cpio -id --quiet usr/sbin/nvx-managed-agent
    )
fi
mv "$stage/usr/sbin/nvx-managed-agent" "$stage/usr/sbin/nvx-managed-agent-real"
cp "$repo/scripts/p8_fault_observer.py" "$stage/p8-fault-observer.py"
cat >"$stage/usr/sbin/nvx-managed-agent" <<'EOF'
#!/bin/sh
/usr/bin/python3 /p8-fault-observer.py >/dev/null 2>&1 &
exec /usr/sbin/nvx-managed-agent-real "$@"
EOF
chmod 0755 "$stage/usr/sbin/nvx-managed-agent"
if [ "$#" -eq 3 ]; then
    cp "$stage/p8-fault-observer.py" "$stage/root/"
    cp "$stage/usr/sbin/nvx-managed-agent" "$stage/usr/sbin/nvx-managed-agent-real" \
        "$stage/root/usr/sbin/"
    diagnostic_erofs_pack
    exit 0
fi
cp "$input" "$output"
(
    cd "$stage"
    printf '%s\n' p8-fault-observer.py usr usr/sbin usr/sbin/nvx-managed-agent-real \
        usr/sbin/nvx-managed-agent |
        cpio -o -H newc --quiet --owner=0:0 | gzip -n
) >>"$output"
sha256sum "$input" "$output" "$stage/usr/sbin/nvx-managed-agent-real"
