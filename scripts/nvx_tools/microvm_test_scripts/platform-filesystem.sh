set -eu
on_exit() {
    status=$?
    if [ "$status" -ne 0 ]; then
        nvx-exit "$status"
    fi
}
trap on_exit EXIT
fail() {
    echo "NVX-PLATFORM-FILESYSTEM-FAIL $1"
    exit "$2"
}
# The restore attached the share to the slot that the platform capture left
# dormant, so the guest mounts it. A mount can succeed before the device
# answers FUSE_INIT, so only the read and the write that follow show that the
# device serves requests once the restore's input gate has released.
mkdir -p /mnt/late
mount -t virtiofs microvm /mnt/late || fail "mount" 80
seed="$(cat /mnt/late/host-seed)" || fail "read" 81
[ "$seed" = NVX-HOST-TO-GUEST ] || fail "read $seed" 82
printf NVX-GUEST-TO-HOST >/mnt/late/guest-result || fail "write" 83
echo NVX-PLATFORM-FILESYSTEM-OK
