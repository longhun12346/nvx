/*
 * Privileged integration probe of the production session implementation.
 * Run in a disposable mount namespace (WSL) or as an initramfs boot probe.
 * Tests real namespace syscalls; it does not mock their success.
 */
#define main nvx_agent_main
#include "../guest/common/nvx-managed-agent.c"
#undef main

static int run_in_session(uint64_t id, const char *command)
{
    struct guest_session *context = guest_session_find(id);
    pid_t pid;
    int status;
    if (context == NULL) return -1;
    pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        char uid[16];
        if (guest_session_enter(context, -1, -1) != 0) {
            perror("enter");
            _exit(125);
        }
        snprintf(uid, sizeof(uid), "%u", context->uid);
        if (clearenv() != 0 || setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin", 1) != 0)
            _exit(125);
        execl("/usr/bin/setpriv", "setpriv", "--reuid", uid, "--regid", uid,
              "--clear-groups", "--no-new-privs", "--bounding-set=-all",
              "--inh-caps=-all", "--ambient-caps=-all",
              "/bin/sh", "-ec", command, (char *)NULL);
        perror("setpriv");
        _exit(125);
    }
    do {
        if (waitpid(pid, &status, 0) == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    } while (errno == EINTR);
    return -1;
}

static pid_t hold_session_mount(struct guest_session *context, const char *target)
{
    pid_t child = fork();
    if (child == 0) {
        for (size_t i = 0; i < GUEST_SESSION_NS_COUNT; ++i) {
            if (setns(context->namespace_fds[i], guest_session_ns_flags[i]) != 0)
                _exit(125);
        }
        if (fchdir(context->root_fd) != 0 || chroot(".") != 0 ||
            chdir(target) != 0) _exit(125);
        raise(SIGSTOP);
        _exit(0);
    }
    return child;
}

#define CHECK(condition, label) do { \
    if (!(condition)) { \
        fprintf(stderr, "P8-PROBE-FAIL %s errno=%d (%s)\n", label, errno, strerror(errno)); \
        guest_session_destroy_all(); \
        return 1; \
    } \
    printf("P8-PROBE-PASS %s\n", label); fflush(stdout); \
} while (0)

/* Exercise the production scheduler, including its real exec cgroup leaves. */
static int probe_parallel_slots(void)
{
    struct exec_slot slots[4] = {0};
    struct agent_config config = {
        .rootfs = "-", .hostname = "probe", .uid = "65534", .gid = "65534",
        .user = "nobody", .home = "/tmp", .direct = 1
    };
    struct control_session control = {0};
    uint64_t started = monotonic_milliseconds();
    size_t i;
    int succeeded = 0;
    control.fd = open("/dev/null", O_WRONLY);
    if (control.fd < 0) return -1;
    for (i = 0; i < 4; ++i) {
        char script[256];
        char **arguments = calloc(4, sizeof(char *));
        struct exec_config exec = {
            .guest_session_id = i < 2 ? 1 : 2,
            .mem_mb = 64, .cpu_percent = 100, .pids_max = 64
        };
        if (arguments == NULL) goto fail;
        snprintf(script, sizeof(script),
                 "echo ready >/tmp/parallel%u; "
                 "n=0; while test ! -e /tmp/parallel%u; do "
                 "n=$((n+1)); test $n -lt 100; sleep .02; done; "
                 "test ! -e /sys/fs/cgroup; echo complete",
                 (unsigned)(i % 2), (unsigned)(1 - i % 2));
        arguments[0] = strdup("/bin/sh");
        arguments[1] = strdup("-ec");
        arguments[2] = strdup(script);
        if (arguments[0] == NULL || arguments[1] == NULL || arguments[2] == NULL) {
            free_arguments(arguments);
            goto fail;
        }
        if (start_slot(&control, &config, &slots[i], 1001 + i, 5000, arguments, &exec) != 0 ||
            (slots[i].flags & SLOT_USED) == 0) {
            free_arguments(arguments);
            goto fail;
        }
    }
    while (monotonic_milliseconds() - started < 8000 && succeeded < 4) {
        reap_children(slots, 4);
        if (guest_session_broken) goto fail;
        for (i = 0; i < 4; ++i) {
            struct exec_slot *slot = &slots[i];
            char cgroup[EXEC_CGROUP_NAME_BYTES];
            int result;
            if ((slot->flags & SLOT_USED) == 0) continue;
            if ((slot->flags & SLOT_STDOUT_OPEN) != 0 && drain_output(slot->stdout_fd) == 1) {
                close(slot->stdout_fd);
                slot->stdout_fd = -1;
                slot->flags &= ~SLOT_STDOUT_OPEN;
            }
            if ((slot->flags & SLOT_STDERR_OPEN) != 0) {
                char diagnostic[512];
                ssize_t size = read(slot->stderr_fd, diagnostic, sizeof(diagnostic));
                if (size > 0) (void)write_all(STDERR_FILENO, diagnostic, (size_t)size);
                if (size == 0) {
                    close(slot->stderr_fd);
                    slot->stderr_fd = -1;
                    slot->flags &= ~SLOT_STDERR_OPEN;
                }
            }
            if ((slot->flags & (SLOT_EXITED | SLOT_STDOUT_OPEN | SLOT_STDERR_OPEN)) != SLOT_EXITED)
                continue;
            if (!WIFEXITED(slot->wait_status) || WEXITSTATUS(slot->wait_status) != 0) {
                fprintf(stderr, "parallel slot %zu status=%d\n", i, slot->wait_status);
                goto fail;
            }
            strcpy(cgroup, slot->cgroup);
            result = finish_slot(&control, &config, slots, 4, slot);
            if (result < 0) goto fail;
            if ((slot->flags & SLOT_USED) == 0) {
                if (access(cgroup, F_OK) == 0 || errno != ENOENT) goto fail;
                ++succeeded;
            }
        }
        usleep(1000);
    }
    if (succeeded == 4) {
        close(control.fd);
        return 0;
    }
fail:
    (void)terminate_all_slots(&config, slots, 4);
    close(control.fd);
    return -1;
}

static int probe_scoped_mounts(void)
{
    struct guest_session *a = guest_session_find(1);
    struct guest_session *b = guest_session_find(2);
    int file;
    CHECK(make_directories("/sessions/a/mounts/data", 1) == 0 &&
          make_directories("/sessions/b/mounts/data", 1) == 0 &&
          chmod("/sessions/a/mounts/data", 0777) == 0 &&
          chmod("/sessions/b/mounts/data", 0777) == 0, "late-mount-fixtures");
    CHECK(guest_session_change_mount(a, "/sessions/a/mounts/data",
                                    "/workspace/mounts/data", 0) == 0 &&
          guest_session_change_mount(b, "/sessions/b/mounts/data",
                                    "/workspace/mounts/data", 0) == 0,
          "same-target-in-independent-sessions");
    CHECK(run_in_session(1, "echo authorized >/workspace/mounts/data/marker") == 0 &&
          run_in_session(2, "test ! -e /workspace/mounts/data/marker") == 0,
          "late-mount-write-isolated");
    CHECK(guest_session_change_mount(a, "/sessions/b/mounts/data",
                                    "/workspace/mounts/foreign", 0) < 0 && errno == EACCES,
          "foreign-source-denied");
    CHECK(guest_session_change_mount(a, "/sessions/a/mounts/data",
                                    "/workspace/mounts/../escape", 0) < 0 && errno == EINVAL,
          "mount-traversal-denied");
    CHECK(guest_session_change_mount(a, "/sessions/a/mounts/data",
                                    "/workspace/mounts/readonly", 1) == 0 &&
          run_in_session(1, "test \"$(cat /workspace/mounts/readonly/marker)\" = authorized; "
                            "! touch /workspace/mounts/readonly/forbidden 2>/dev/null") == 0,
          "recursive-readonly-enforced");
    CHECK(guest_session_change_mount(a, NULL, "/workspace/mounts/data", 0) == 0 &&
          run_in_session(1, "test ! -e /workspace/mounts/data/marker; "
                            "test -e /workspace/mounts/readonly/marker") == 0,
          "private-unmount-preserves-other-authorized-view");
    CHECK(run_in_session(2, "echo alive >/workspace/mounts/data/b") == 0,
          "b-mount-survives-a-unmount");
    CHECK(guest_session_change_mount(a, NULL, "/workspace/mounts/readonly", 0) == 0 &&
          guest_session_change_mount(b, NULL, "/workspace/mounts/data", 0) == 0,
          "all-private-directory-mounts-revoked");
    file = open("/sessions/a/mounts/file", O_CREAT | O_EXCL | O_WRONLY, 0644);
    CHECK(file >= 0 && write_all(file, "file\n", 5) == 0, "file-source");
    close(file);
    CHECK(guest_session_change_mount(a, "/sessions/a/mounts/file",
                                    "/workspace/mounts/file", 1) == 0 &&
          run_in_session(1, "test \"$(cat /workspace/mounts/file)\" = file") == 0 &&
          guest_session_change_mount(a, NULL, "/workspace/mounts/file", 0) == 0,
          "file-bind-and-strict-unmount");
    CHECK(guest_session_change_mount(a, "/sessions/a/mounts/data",
                                    "/workspace/mounts/busy", 0) == 0,
          "busy-revoke-fixture");
    {
        pid_t holder = hold_session_mount(a, "/workspace/mounts/busy");
        int status;
        CHECK(holder > 0 && waitpid(holder, &status, WUNTRACED) == holder &&
              WIFSTOPPED(status), "busy-revoke-holder");
        CHECK(guest_session_change_mount(a, NULL, "/workspace/mounts/busy", 0) < 0 &&
              guest_session_broken, "busy-revoke-escalates-group-failure");
        kill(holder, SIGKILL);
        waitpid(holder, &status, 0);
        guest_session_broken = 0;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int sentinel;
    struct stat before, after;
    char command[512];
    uint8_t payload[128] = {0};
    char decoded[MAX_GUEST_PATH];
    uint64_t id;
    const char *source = "/sessions/a/workspace";
    const char *path_b = "/sessions/b/workspace";
    CHECK(geteuid() == 0, "requires-root");
    CHECK(guest_session_mkdir("/run/nvx", 0700) == 0 &&
          guest_session_mkdir(GUEST_SESSION_STORE, 0700) == 0 &&
          mount("tmpfs", GUEST_SESSION_STORE, "tmpfs", MS_NOSUID | MS_NODEV, "size=2m") == 0 &&
          guest_session_mkdir("/sessions", 0755) == 0 &&
          mount("tmpfs", "/sessions", "tmpfs", MS_NOSUID | MS_NODEV, "size=8m") == 0,
          "disposable-agent-state");
    CHECK(make_directories(source, 1) == 0 && make_directories(path_b, 1) == 0 &&
          chmod(source, 0777) == 0 && chmod(path_b, 0777) == 0, "workspace-fixtures");
    write_u16(payload, 1);
    write_u64(payload + 4, 1);
    write_u32(payload + 12, (uint32_t)strlen(source));
    memcpy(payload + 16, source, strlen(source));
    int share_network = -1;
    CHECK(guest_session_decode(payload, 16 + (uint32_t)strlen(source), &id, decoded,
                               &share_network) == 0 &&
          id == 1 && strcmp(decoded, source) == 0 && share_network == 0, "session-wire");
    payload[2] = 1;
    share_network = -1;
    CHECK(guest_session_decode(payload, 16 + (uint32_t)strlen(source), &id, decoded,
                               &share_network) == 0 && share_network == 1,
          "shared-network-policy-decoded");
    payload[2] = 2;
    CHECK(guest_session_decode(payload, 16 + (uint32_t)strlen(source), &id, decoded,
                               &share_network) < 0,
          "unknown-network-policy-refused");
    payload[2] = 0;
    CHECK(symlink("/etc", "/sessions/symlink") == 0 &&
          guest_session_open_workspace("/sessions/symlink") < 0, "workspace-symlink-refused");
    sentinel = open("/etc/passwd", O_RDONLY);
    CHECK(sentinel >= 0 && fstat(sentinel, &before) == 0, "agent-secret-fd");
    CHECK(guest_session_create(1, source, 0) == 0, "create-a");
    CHECK(guest_session_create(2, path_b, 0) == 0, "create-b");
    if (argc == 2 && strcmp(argv[1], "--scheduler") == 0) {
        CHECK(probe_parallel_slots() == 0, "production-scheduler-two-by-two-cgroups");
    }
    CHECK(run_in_session(1,
          "test \"$(id -u)\" = 100000; test \"$(id -G)\" = 100000; "
          "test -z \"$(ls -A /sessions)\"; test -z \"$(ls -A /run)\"; "
          "test -z \"$(ls -A /sys)\"; test ! -e /proc/1/root/run/nvx; "
          "grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status; "
          "test \"$(awk '/^NSpid:/ {print NF}' /proc/self/status)\" = 2; "
          "! kill -TERM 1 2>/dev/null; "
          "test \"$(ls /proc/self/fd | wc -l)\" -le 4") == 0,
          "identity-proc-capabilities-fds");
    CHECK(run_in_session(1,
          "echo a >/tmp/private; echo credentials >/home/session/credentials; "
          "echo ipc >/dev/shm/private; echo workspace >/workspace/owner; "
          "test ! -w /usr/bin; test ! -w /etc/passwd") == 0, "a-private-state");
    CHECK(run_in_session(1,
          "test \"$(cat /tmp/private)\" = a; "
          "test \"$(cat /home/session/credentials)\" = credentials; "
          "test \"$(cat /dev/shm/private)\" = ipc; "
          "test \"$(cat /workspace/owner)\" = workspace") == 0, "same-session-state");
    CHECK(run_in_session(2,
          "test \"$(id -u)\" = 100001; test ! -e /tmp/private; "
          "test ! -e /home/session/credentials; test ! -e /dev/shm/private; "
          "test ! -e /workspace/owner; "
          "test ! -e /workspace/../a/workspace/owner") == 0, "cross-session-state");
    CHECK(run_in_session(1,
          "python3 -c 'import ctypes; l=ctypes.CDLL(None,use_errno=True); "
          "assert l.shmget(0x4e565841,1,0o600|0o1000)>=0; "
          "assert l.semget(0x4e565842,1,0o600|0o1000)>=0; "
          "assert l.msgget(0x4e565843,0o600|0o1000)>=0'") == 0,
          "same-session-sysv-ipc");
    CHECK(run_in_session(2,
          "python3 -c 'import ctypes; l=ctypes.CDLL(None,use_errno=True); "
          "assert all(fn(key,*args)<0 and ctypes.get_errno()==2 for key,fn,args in "
          "[(0x4e565841,l.shmget,(1,0o600)),(0x4e565842,l.semget,(1,0o600)),"
          "(0x4e565843,l.msgget,(0o600,))])'") == 0,
          "cross-session-sysv-ipc-denied");
    CHECK(probe_scoped_mounts() == 0, "scoped-mount-matrix");
    /* A daemon survives between calls in this direct lifecycle probe. The
     * production exec cgroup additionally removes such descendants per exec. */
    CHECK(run_in_session(1,
          "python3 -c 'import os,socket; s=socket.socket(); "
          "s.bind((\"127.0.0.1\",35181)); s.listen(); "
          "pid=os.fork(); "
          "os._exit(0) if pid else s.accept();'") == 0, "a-loopback-server");
    CHECK(run_in_session(2,
          "python3 -c 'import socket; s=socket.socket(); s.settimeout(1); "
          "assert s.connect_ex((\"127.0.0.1\",35181)) != 0'") == 0,
          "cross-session-loopback-denied");
    CHECK(run_in_session(1,
          "python3 -c 'import socket; s=socket.socket(); s.settimeout(1); "
          "s.connect((\"127.0.0.1\",35181))'") == 0, "same-session-loopback");
    CHECK(fstat(sentinel, &after) == 0 && before.st_ino == after.st_ino,
          "agent-descriptors-preserved");
    close(sentinel);
    CHECK(guest_session_destroy(guest_session_find(1)) == 0, "close-a");
    CHECK(run_in_session(2, "echo b >/tmp/alive; test \"$(cat /tmp/alive)\" = b") == 0,
          "b-survives-a-close");
    CHECK(guest_session_create(1, source, 0) < 0 && errno == ESTALE, "id-reuse-refused");
    CHECK(guest_session_create(3, source, 0) == 0, "reopen-new-id");
    CHECK(run_in_session(3,
          "test ! -e /tmp/private; test ! -e /home/session/credentials; "
          "test ! -e /dev/shm/private; test \"$(cat /workspace/owner)\" = workspace") == 0,
          "private-state-reset-authorized-workspace-persists");
    CHECK(guest_session_destroy(guest_session_find(2)) == 0 &&
          guest_session_destroy(guest_session_find(3)) == 0 &&
          !guest_session_broken, "cleanup-all");
    snprintf(command, sizeof(command), "%s/1", GUEST_SESSION_STORE);
    CHECK(access(command, F_OK) < 0 && errno == ENOENT, "session-directories-removed");
    {
        /* A session created with a shared network never leaves the VM's own namespace. */
        char agent_net[64], check[256];
        ssize_t length = readlink("/proc/self/ns/net", agent_net, sizeof(agent_net) - 1);
        CHECK(length > 0, "agent-net-namespace");
        agent_net[length] = '\0';
        CHECK(guest_session_create(10, source, 1) == 0, "create-shared-network");
        snprintf(check, sizeof(check),
                 "test \"$(readlink /proc/self/ns/net)\" = '%s'", agent_net);
        CHECK(run_in_session(10, check) == 0, "shared-network-is-the-vm-namespace");
        CHECK(guest_session_destroy(guest_session_find(10)) == 0 && !guest_session_broken,
              "cleanup-shared-network");
    }
    guest_session_legacy_used = 1;
    CHECK(guest_session_create(11, source, 0) < 0 && errno == EXDEV, "legacy-migration-refused");
    guest_session_legacy_used = 0;
    CHECK(guest_session_create(11, source, 0) == 0, "fault-injection-session");
    {
        struct guest_session *faulted = guest_session_find(11);
        pid_t keeper = faulted->keeper;
        CHECK(kill(keeper, SIGKILL) == 0, "fault-injection-kill-keeper");
        CHECK(waitpid(keeper, NULL, 0) == keeper, "fault-injection-reap-keeper");
        guest_session_reaped(keeper);
        CHECK(guest_session_broken && guest_session_find(11)->keeper == 0,
              "keeper-loss-escalates-group-failure");
        guest_session_destroy_all();
    }
    puts("P8-PROBE-COMPLETE");
    return 0;
}
