/*
 * Guest-owned session contexts. Included by the managed agent so the lifecycle
 * and exec scheduler share one authoritative table. Nothing here accepts a
 * workload-supplied namespace handle or derives identity from its environment.
 */
#include <dirent.h>
#include <linux/capability.h>
#include <linux/mount.h>
#include <net/if.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#define GUEST_SESSION_MAX 64U
#define GUEST_SESSION_NS_COUNT 5U
#define GUEST_SESSION_STORE "/run/nvx/session-store"
#define GUEST_SESSION_STACK (128U * 1024U)

struct guest_session {
    uint64_t id;
    pid_t keeper;
    uint32_t uid;
    int root_fd;
    int namespace_fds[GUEST_SESSION_NS_COUNT];
    char directory[128];
    char source_parent[MAX_GUEST_PATH];
    char *mount_targets[MAX_RUNTIME_MAPPINGS];
};

static struct guest_session guest_sessions[GUEST_SESSION_MAX];
static uint64_t guest_session_highest_id;
static uint32_t guest_session_next_uid = 100000U;
static int guest_session_broken;
/* Once ordinary user code ran, private sessions require a new VM. */
static int guest_session_legacy_used;
static const char *const guest_session_ns_names[GUEST_SESSION_NS_COUNT] = {
    "mnt", "ipc", "uts", "net", "pid"
};
static const int guest_session_ns_flags[GUEST_SESSION_NS_COUNT] = {
    CLONE_NEWNS, CLONE_NEWIPC, CLONE_NEWUTS, CLONE_NEWNET, CLONE_NEWPID
};

static struct guest_session *guest_session_find(uint64_t id)
{
    size_t i;
    for (i = 0; i < GUEST_SESSION_MAX; ++i) {
        if (id != 0 && guest_sessions[i].id == id) {
            return &guest_sessions[i];
        }
    }
    return NULL;
}

/*
 * Close every inherited descriptor except the two explicitly delegated ones.
 * /proc is still the trusted agent procfs when this runs. An enumeration error
 * fails the launch; it must never turn into a workload with control handles.
 */
static int guest_session_close_fds(int keep_a, int keep_b)
{
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    if (directory == NULL) {
        return -1;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        char *end;
        long fd = strtol(entry->d_name, &end, 10);
        if (*end == '\0' && fd > 2 && fd <= INT32_MAX &&
            fd != dirfd(directory) && fd != keep_a && fd != keep_b) {
            close((int)fd);
        }
        errno = 0;
    }
    {
        int error = errno;
        closedir(directory);
        errno = error;
        return error == 0 ? 0 : -1;
    }
}

static int guest_session_decode(
    const uint8_t *payload, uint32_t length, uint64_t *id, char *workspace)
{
    uint32_t path_length;
    if (length < 16 || read_u16(payload) != 1 || read_u16(payload + 2) != 0) {
        errno = EINVAL;
        return -1;
    }
    *id = read_u64(payload + 4);
    path_length = read_u32(payload + 12);
    if (*id == 0 || path_length == 0 || path_length >= MAX_GUEST_PATH ||
        path_length != length - 16 || memchr(payload + 16, 0, path_length) != NULL) {
        errno = EINVAL;
        return -1;
    }
    memcpy(workspace, payload + 16, path_length);
    workspace[path_length] = '\0';
    if (strncmp(workspace, "/sessions/", 10) != 0 || !safe_path(workspace, 1) ||
        path_length <= 20 || strcmp(workspace + path_length - 10, "/workspace") != 0 ||
        strchr(workspace + 10, '/') != workspace + path_length - 10) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/* Resolve an agent-owned workspace without following a symlink at any level. */
static int guest_session_open_workspace(const char *path)
{
    char copy[MAX_GUEST_PATH];
    char *save = NULL;
    char *part;
    int current = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (current < 0 || strlen(path) >= sizeof(copy)) {
        if (current >= 0) close(current);
        errno = EINVAL;
        return -1;
    }
    strcpy(copy, path);
    for (part = strtok_r(copy, "/", &save); part != NULL;
         part = strtok_r(NULL, "/", &save)) {
        int next = openat(current, part, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int error = errno;
        close(current);
        if (next < 0) {
            errno = error;
            return -1;
        }
        current = next;
    }
    return current;
}

static int guest_session_mkdir(const char *path, mode_t mode)
{
    struct stat status;
    if (mkdir(path, mode) != 0 && errno != EEXIST) return -1;
    if (lstat(path, &status) != 0 || !S_ISDIR(status.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    return 0;
}

struct guest_session_start {
    struct guest_session *context;
    int ready_fd;
    int workspace_fd;
    const char *workspace_path;
};
static const char *guest_session_setup_stage = "descriptors";

/* Paths below the overlay root are trusted until readiness is acknowledged. */
static int guest_session_empty_mount(const char *path, const char *options)
{
    if (guest_session_mkdir(path, 0755) != 0) return -1;
    return mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV, options);
}

static int guest_session_setup_root(const struct guest_session_start *start)
{
    char options[512];
    char workspace[64];
    char hostname[64];
    char identity[256];
    size_t i;
    int fd;
    static const char *const hidden[] = {"run", "root", "sessions", "mnt", "sys"};
    static const char *const devices[] = {"null", "zero", "random", "urandom"};
    struct guest_session *context = start->context;

    guest_session_setup_stage = "readonly-lower";
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0 ||
        mount("tmpfs", context->directory, "tmpfs", MS_NOSUID | MS_NODEV,
              "size=64m,nr_inodes=16384,mode=0700") != 0 ||
        chdir(context->directory) != 0 ||
        mkdir("lower", 0700) != 0 || mkdir("upper", 0755) != 0 ||
        mkdir("work", 0700) != 0 || mkdir("root", 0700) != 0 ||
        mount("/", "lower", NULL, MS_BIND, NULL) != 0 ||
        mount(NULL, "lower", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY |
              MS_NOSUID | MS_NODEV, NULL) != 0) return -1;
    snprintf(options, sizeof(options), "lowerdir=%s/lower,upperdir=%s/upper,workdir=%s/work",
             context->directory, context->directory, context->directory);
    guest_session_setup_stage = "overlay";
    if (mount("overlay", "root", "overlay", MS_NOSUID | MS_NODEV, options) != 0 ||
        chdir("root") != 0) return -1;
    /*
     * These small empty mounts mask agent state, boot homes and mountpoints.
     * HOME/tmp and shm have explicit capacities. The 64 MiB overlay upper is
     * separately bounded; session admission must account for these capacities.
     */
    guest_session_setup_stage = "mask-agent-state";
    for (i = 0; i < sizeof(hidden) / sizeof(hidden[0]); ++i) {
        if (guest_session_empty_mount(hidden[i],
                "size=1m,nr_inodes=256,mode=0755") != 0) return -1;
    }
    guest_session_setup_stage = "private-writable-directories";
    if (guest_session_empty_mount("tmp", "size=32m,nr_inodes=8192,mode=1777") != 0 ||
        guest_session_empty_mount("home", "size=32m,nr_inodes=8192,mode=0755") != 0 ||
        mkdir("home/session", 0700) != 0 ||
        chown("home/session", context->uid, context->uid) != 0 ||
        guest_session_empty_mount("dev", "size=1m,nr_inodes=256,mode=0755") != 0)
        return -1;
    guest_session_setup_stage = "devices";
    for (i = 0; i < sizeof(devices) / sizeof(devices[0]); ++i) {
        char source[64], target[64];
        snprintf(source, sizeof(source), "/dev/%s", devices[i]);
        snprintf(target, sizeof(target), "dev/%s", devices[i]);
        fd = open(target, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (fd < 0) return -1;
        close(fd);
        if (mount(source, target, NULL, MS_BIND, NULL) != 0 ||
            mount(NULL, target, NULL, MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NOEXEC, NULL) != 0)
            return -1;
    }
    if (symlink("/proc/self/fd", "dev/fd") != 0 ||
        symlink("/proc/self/fd/0", "dev/stdin") != 0 ||
        symlink("/proc/self/fd/1", "dev/stdout") != 0 ||
        symlink("/proc/self/fd/2", "dev/stderr") != 0 ||
        guest_session_empty_mount("dev/shm", "size=16m,nr_inodes=4096,mode=1777") != 0 ||
        guest_session_mkdir("workspace", 0755) != 0) return -1;
    guest_session_setup_stage = "workspace-proc";
    snprintf(workspace, sizeof(workspace), "/proc/self/fd/%d", start->workspace_fd);
    /* Recursive bind preserves explicitly authorized nested ro/rw mount flags. */
    if (mount(workspace, "workspace", NULL, MS_BIND | MS_REC, NULL) != 0 ||
        guest_session_mkdir("proc", 0555) != 0 ||
        mount("proc", "proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0)
        return -1;
    guest_session_setup_stage = "identity";
    snprintf(hostname, sizeof(hostname), "nvx-session-%llu", (unsigned long long)context->id);
    if (sethostname(hostname, strlen(hostname)) != 0) return -1;
    /* Fresh account files: no earlier session account or credentials survive. */
    snprintf(identity, sizeof(identity),
             "root:x:0:0:root:/root:/bin/false\nsession:x:%u:%u:session:/home/session:/bin/sh\n",
             context->uid, context->uid);
    fd = open("etc/passwd", O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (write_all(fd, identity, strlen(identity)) != 0) { close(fd); return -1; }
    close(fd);
    snprintf(identity, sizeof(identity), "root:x:0:\nsession:x:%u:\n", context->uid);
    fd = open("etc/group", O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (write_all(fd, identity, strlen(identity)) != 0) { close(fd); return -1; }
    close(fd);
    guest_session_setup_stage = "chroot-network";
    if (chroot(".") != 0 || chdir("/") != 0) return -1;
    /* A new netns has no external interfaces. Enable only its own loopback. */
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    {
        struct ifreq request = {0};
        strcpy(request.ifr_name, "lo");
        request.ifr_flags = IFF_UP | IFF_LOOPBACK;
        if (ioctl(fd, SIOCSIFFLAGS, &request) != 0) { close(fd); return -1; }
    }
    close(fd);
    return 0;
}

static void guest_session_sigchld(int signal_number)
{
    (void)signal_number;
}

static int guest_session_keeper(void *argument)
{
    struct guest_session_start local = *(const struct guest_session_start *)argument;
    const struct guest_session_start *start = &local;
    int result = 0;
    sigset_t blocked, empty;
    struct sigaction action = {0};
    struct __user_cap_header_struct capability_header = {
        .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0
    };
    struct __user_cap_data_struct capability_data[2] = {{0}, {0}};
    int null_fd;
    int reopened;
    struct stat pinned, resolved;

    /*
     * The inherited O_PATH refers to the agent's mount object. Bind-mounting
     * that object from the cloned namespace is rejected by Linux. Reopen the
     * protected path in this namespace, and require the same pinned object.
     * The single agent is awaiting readiness, so no mapping mutation can race.
     */
    reopened = guest_session_open_workspace(start->workspace_path);
    if (reopened < 0 || fstat(local.workspace_fd, &pinned) != 0 ||
        fstat(reopened, &resolved) != 0 || pinned.st_dev != resolved.st_dev ||
        pinned.st_ino != resolved.st_ino) {
        result = ESTALE;
        (void)write_all(start->ready_fd, &result, sizeof(result));
        _exit(125);
    }
    close(local.workspace_fd);
    local.workspace_fd = reopened;
    /* Do not retain control, namespace or another session's root descriptors. */
    if (guest_session_close_fds(start->ready_fd, start->workspace_fd) != 0 ||
        guest_session_setup_root(start) != 0) {
        result = errno == 0 ? EIO : errno;
        dprintf(STDERR_FILENO, "NVX-SESSION-ERROR stage=%s errno=%d\n",
                guest_session_setup_stage, result);
        (void)write_all(start->ready_fd, &result, sizeof(result));
        _exit(125);
    }
    close(start->workspace_fd);
    null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd < 0) _exit(125);
    for (int i = 0; i < 3; ++i) {
        if (dup2(null_fd, i) < 0) _exit(125);
    }
    if (null_fd > 2) close(null_fd);
    action.sa_handler = guest_session_sigchld;
    sigemptyset(&action.sa_mask);
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGCHLD);
    sigemptyset(&empty);
    if (sigaction(SIGCHLD, &action, NULL) != 0 ||
        sigprocmask(SIG_BLOCK, &blocked, NULL) != 0 ||
        prctl(PR_SET_DUMPABLE, 0) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(125);
    for (int cap = 0; cap <= CAP_LAST_CAP; ++cap) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && errno != EINVAL) _exit(125);
    }
    if (syscall(SYS_capset, &capability_header, capability_data) != 0) _exit(125);
    if (write_all(start->ready_fd, &result, sizeof(result)) != 0) _exit(125);
    close(start->ready_fd);
    /* PID 1 reaps all adopted descendants; no request-serving code runs here. */
    for (;;) {
        while (waitpid(-1, NULL, WNOHANG) > 0) {}
        sigsuspend(&empty);
    }
}

static void guest_session_release_fds(struct guest_session *context)
{
    size_t i;
    if (context->root_fd >= 0) close(context->root_fd);
    context->root_fd = -1;
    for (i = 0; i < GUEST_SESSION_NS_COUNT; ++i) {
        if (context->namespace_fds[i] >= 0) close(context->namespace_fds[i]);
        context->namespace_fds[i] = -1;
    }
}

/*
 * Kill PID 1 and wait for kernel teardown. A timeout is an isolation fault,
 * never successful cleanup. No lazy unmount can hide surviving references.
 */
static int guest_session_destroy(struct guest_session *context)
{
    unsigned attempt;
    int reaped = context->keeper <= 0;
    if (!reaped && kill(context->keeper, SIGKILL) != 0 && errno != ESRCH) return -1;
    for (attempt = 0; !reaped && attempt < 200; ++attempt) {
        pid_t pid = waitpid(context->keeper, NULL, WNOHANG);
        if (pid == context->keeper || (pid < 0 && errno == ECHILD)) {
            reaped = 1;
            break;
        }
        if (pid < 0 && errno != EINTR) break;
        usleep(10000);
    }
    if (!reaped) {
        guest_session_broken = 1;
        errno = EBUSY;
        return -1;
    }
    guest_session_release_fds(context);
    if (rmdir(context->directory) != 0 && errno != ENOENT) {
        guest_session_broken = 1;
        return -1;
    }
    for (size_t i = 0; i < MAX_RUNTIME_MAPPINGS; ++i) free(context->mount_targets[i]);
    memset(context, 0, sizeof(*context));
    return 0;
}

static int guest_session_create(uint64_t id, const char *workspace)
{
    size_t i;
    struct guest_session *context = NULL;
    struct guest_session_start start;
    int ready[2] = {-1, -1};
    int result = 0;
    int source;
    void *stack;
    struct pollfd poller;
    if (guest_session_broken || guest_session_legacy_used) {
        errno = EXDEV;
        return -1;
    }
    if (id == 0 || id <= guest_session_highest_id) { errno = ESTALE; return -1; }
    for (i = 0; i < GUEST_SESSION_MAX; ++i) {
        if (guest_sessions[i].id == 0) { context = &guest_sessions[i]; break; }
    }
    if (context == NULL || guest_session_next_uid == UINT32_MAX) {
        errno = ENOSPC;
        return -1;
    }
    source = guest_session_open_workspace(workspace);
    if (source < 0) return -1;
    if (guest_session_mkdir("/run/nvx", 0700) != 0 ||
        guest_session_mkdir(GUEST_SESSION_STORE, 0700) != 0 ||
        chmod(GUEST_SESSION_STORE, 0700) != 0 || pipe2(ready, O_CLOEXEC) != 0) {
        close(source);
        return -1;
    }
    memset(context, 0, sizeof(*context));
    context->root_fd = -1;
    for (i = 0; i < GUEST_SESSION_NS_COUNT; ++i) context->namespace_fds[i] = -1;
    context->id = id;
    snprintf(context->source_parent, sizeof(context->source_parent), "%s", workspace);
    *strrchr(context->source_parent, '/') = '\0';
    context->uid = guest_session_next_uid++;
    guest_session_highest_id = id; /* failed attempts cannot reuse an identity */
    snprintf(context->directory, sizeof(context->directory), "%s/%llu",
             GUEST_SESSION_STORE, (unsigned long long)id);
    if (mkdir(context->directory, 0700) != 0) {
        result = errno;
        goto fail;
    }
    stack = mmap(NULL, GUEST_SESSION_STACK, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) { result = errno; goto fail; }
    start.context = context;
    start.ready_fd = ready[1];
    start.workspace_fd = source;
    start.workspace_path = workspace;
    context->keeper = clone(guest_session_keeper, (char *)stack + GUEST_SESSION_STACK,
        CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWPID | SIGCHLD,
        &start);
    result = context->keeper < 0 ? errno : 0;
    munmap(stack, GUEST_SESSION_STACK);
    close(ready[1]);
    ready[1] = -1;
    if (result != 0) goto fail;
    poller.fd = ready[0];
    poller.events = POLLIN;
    poller.revents = 0;
    if (poll(&poller, 1, 5000) <= 0 ||
        read(ready[0], &result, sizeof(result)) != sizeof(result)) {
        result = ETIMEDOUT;
        goto fail;
    }
    if (result != 0) goto fail;
    for (i = 0; i < GUEST_SESSION_NS_COUNT; ++i) {
        char path[96];
        snprintf(path, sizeof(path), "/proc/%d/ns/%s", context->keeper, guest_session_ns_names[i]);
        context->namespace_fds[i] = open(path, O_RDONLY | O_CLOEXEC);
        if (context->namespace_fds[i] < 0) { result = errno; goto fail; }
    }
    {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/root", context->keeper);
        context->root_fd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (context->root_fd < 0) { result = errno; goto fail; }
    }
    close(ready[0]);
    close(source);
    return 0;
fail:
    close(source);
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    if (guest_session_destroy(context) != 0) guest_session_broken = 1;
    errno = result;
    return -1;
}

/* Called only in a forked launch child, before any user code or privilege drop. */
static int guest_session_enter(
    const struct guest_session *context, int config_fd, int launch_fd)
{
    size_t i;
    pid_t child;
    int status;
    for (i = 0; i < GUEST_SESSION_NS_COUNT; ++i) {
        if (setns(context->namespace_fds[i], guest_session_ns_flags[i]) != 0) return -1;
    }
    if (fchdir(context->root_fd) != 0 || chroot(".") != 0 || chdir("/") != 0)
        return -1;
    /*
     * The joining process still has its old PID namespace. Its child is born
     * in the target namespace, and is the only one allowed to execute user code.
     */
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        if (guest_session_close_fds(config_fd, launch_fd) != 0) return -1;
        return 0;
    }
    close(config_fd);
    close(launch_fd);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    for (;;) {
        if (waitpid(child, &status, 0) == child) break;
        if (errno != EINTR) _exit(125);
    }
    if (WIFEXITED(status)) _exit(WEXITSTATUS(status));
    if (WIFSIGNALED(status)) {
        signal(WTERMSIG(status), SIG_DFL);
        raise(WTERMSIG(status));
    }
    _exit(125);
}

static void guest_session_reaped(pid_t pid)
{
    size_t i;
    for (i = 0; i < GUEST_SESSION_MAX; ++i) {
        if (guest_sessions[i].id != 0 && guest_sessions[i].keeper == pid) {
            guest_sessions[i].keeper = 0;
            guest_session_broken = 1;
        }
    }
}

static void guest_session_destroy_all(void)
{
    size_t i;
    for (i = 0; i < GUEST_SESSION_MAX; ++i) {
        if (guest_sessions[i].id != 0 &&
            guest_session_destroy(&guest_sessions[i]) != 0) guest_session_broken = 1;
    }
}

static int guest_session_mount_target_valid(const char *target)
{
    const char *leaf;
    size_t length;
    if (strncmp(target, "/workspace/mounts/", 18) != 0) return 0;
    leaf = target + 18;
    length = strlen(leaf);
    if (length == 0 || length > 255 || strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0)
        return 0;
    for (; *leaf; ++leaf) {
        if (!((*leaf >= 'A' && *leaf <= 'Z') || (*leaf >= 'a' && *leaf <= 'z') ||
              (*leaf >= '0' && *leaf <= '9') || *leaf == '_' || *leaf == '-' || *leaf == '.'))
            return 0;
    }
    return 1;
}

static int guest_session_mount_decode(
    const uint8_t *payload, uint32_t length, uint64_t *id,
    char *source, char *target, int *read_only)
{
    uint16_t source_len, target_len, flags;
    if (length < 14) { errno = EINVAL; return -1; }
    *id = read_u64(payload);
    flags = read_u16(payload + 8);
    source_len = read_u16(payload + 10);
    target_len = read_u16(payload + 12);
    if (*id == 0 || flags > 1 || source_len == 0 || source_len >= MAX_GUEST_PATH ||
        target_len == 0 || target_len >= MAX_GUEST_PATH ||
        length != 14U + source_len + target_len ||
        memchr(payload + 14, 0, source_len + target_len) != NULL) {
        errno = EINVAL;
        return -1;
    }
    memcpy(source, payload + 14, source_len);
    source[source_len] = 0;
    memcpy(target, payload + 14 + source_len, target_len);
    target[target_len] = 0;
    if (!safe_path(source, 1) || !guest_session_mount_target_valid(target)) {
        errno = EINVAL;
        return -1;
    }
    *read_only = flags;
    return 0;
}

/* No symlink, including a file leaf, may turn a source or target into another path. */
static int guest_session_open_mount_source(const char *path)
{
    char parent[MAX_GUEST_PATH];
    char *leaf;
    int parent_fd, result;
    struct stat status;
    if (strlen(path) >= sizeof(parent) || !safe_path(path, 1)) {
        errno = EINVAL;
        return -1;
    }
    strcpy(parent, path);
    leaf = strrchr(parent, '/');
    if (leaf == parent) { errno = EINVAL; return -1; }
    *leaf++ = 0;
    parent_fd = guest_session_open_workspace(parent);
    if (parent_fd < 0) return -1;
    result = openat(parent_fd, leaf, O_PATH | O_CLOEXEC | O_NOFOLLOW);
    close(parent_fd);
    if (result >= 0 && (fstat(result, &status) != 0 ||
        (!S_ISDIR(status.st_mode) && !S_ISREG(status.st_mode)))) {
        close(result);
        errno = EINVAL;
        return -1;
    }
    return result;
}

static int guest_session_prepare_mount_target(const char *target, int directory)
{
    int parent, mounts, result;
    struct stat status;
    parent = open("/workspace", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) return -1;
    if (mkdirat(parent, "mounts", 0755) != 0 && errno != EEXIST) {
        close(parent);
        return -1;
    }
    mounts = openat(parent, "mounts", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(parent);
    if (mounts < 0) return -1;
    if (directory) {
        if (mkdirat(mounts, target + 18, 0755) != 0 && errno != EEXIST) {
            close(mounts);
            return -1;
        }
    } else {
        result = openat(mounts, target + 18, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC |
                        O_NOFOLLOW, 0644);
        if (result >= 0) close(result);
        else if (errno != EEXIST) { close(mounts); return -1; }
    }
    result = openat(mounts, target + 18, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    close(mounts);
    if (result >= 0 && (fstat(result, &status) != 0 ||
        (directory ? !S_ISDIR(status.st_mode) : !S_ISREG(status.st_mode)))) {
        close(result);
        errno = EINVAL;
        return -1;
    }
    return result;
}

/*
 * The source mount is cloned before entering the target namespace. move_mount
 * consumes a detached mount FD, so it neither resolves an agent path in an
 * untrusted root nor depends on /proc/self in a different PID namespace.
 */
static int guest_session_mount_worker(
    const struct guest_session *context, int tree, const char *target, int directory)
{
    int target_fd, result, saved;
    if (setns(context->namespace_fds[0], CLONE_NEWNS) != 0 ||
        fchdir(context->root_fd) != 0 || chroot(".") != 0 || chdir("/") != 0) return -1;
    if (tree >= 0) {
        target_fd = guest_session_prepare_mount_target(target, directory);
        if (target_fd < 0) return -1;
        result = syscall(SYS_move_mount, tree, "", target_fd, "",
                         MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH);
        saved = errno;
        close(target_fd);
        errno = saved;
        return result;
    }
    /*
     * Move the pinned mount to a root-only staging point, then close its FD and
     * strictly unmount it. The private path cannot be redirected by host-side
     * workspace mutations. A surviving open handle makes umount fail; no
     * MNT_DETACH is used and the caller must retire the VM on such a failure.
     */
    target_fd = guest_session_open_mount_source(target);
    if (target_fd < 0) return -1;
    {
        struct stat status;
        int staging;
        const char *destination = "/run/nvx-revoke/mount";
        if (fstat(target_fd, &status) != 0 ||
            guest_session_mkdir("/run/nvx-revoke", 0700) != 0) {
            close(target_fd);
            return -1;
        }
        directory = S_ISDIR(status.st_mode);
        if (directory) {
            result = mkdir(destination, 0700);
        } else {
            result = open(destination, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
            if (result >= 0) { close(result); result = 0; }
        }
        if (result != 0) { close(target_fd); return -1; }
        staging = open(destination, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (staging < 0) { close(target_fd); return -1; }
        result = syscall(SYS_move_mount, target_fd, "", staging, "",
                         MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH);
        saved = errno;
        close(staging);
        close(target_fd);
        if (result != 0) { errno = saved; return -1; }
        if (umount(destination) != 0) return -1;
        return directory ? rmdir(destination) : unlink(destination);
    }
}

static int guest_session_change_mount(
    struct guest_session *context, const char *source, const char *target, int read_only)
{
    int pipes[2], tree = -1, directory = 0, result = 0, status = 0, confirmed = 0;
    pid_t child;
    unsigned attempt;
    size_t slot = MAX_RUNTIME_MAPPINGS;
    char *copy = NULL;
    struct pollfd poller;
    if (!guest_session_mount_target_valid(target)) { errno = EINVAL; return -1; }
    for (size_t i = 0; i < MAX_RUNTIME_MAPPINGS; ++i) {
        if (context->mount_targets[i] != NULL && strcmp(context->mount_targets[i], target) == 0) {
            if (source != NULL) { errno = EEXIST; return -1; }
            slot = i;
            break;
        }
        if (source != NULL && context->mount_targets[i] == NULL && slot == MAX_RUNTIME_MAPPINGS)
            slot = i;
    }
    if (slot == MAX_RUNTIME_MAPPINGS) { errno = source == NULL ? ENOENT : ENOSPC; return -1; }
    if (source != NULL) {
        struct stat source_status;
        struct mount_attr attributes = {0};
        size_t prefix_len = strlen(context->source_parent);
        int source_fd;
        if (strncmp(source, context->source_parent, prefix_len) != 0 ||
            strncmp(source + prefix_len, "/mounts/", 8) != 0) {
            errno = EACCES;
            return -1;
        }
        source_fd = guest_session_open_mount_source(source);
        if (source_fd < 0) return -1;
        if (fstat(source_fd, &source_status) != 0) { close(source_fd); return -1; }
        directory = S_ISDIR(source_status.st_mode);
        tree = syscall(SYS_open_tree, source_fd, "",
                       OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH | AT_RECURSIVE);
        close(source_fd);
        if (tree < 0) return -1;
        attributes.attr_set = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;
        if (read_only) attributes.attr_set |= MOUNT_ATTR_RDONLY;
        if (syscall(SYS_mount_setattr, tree, "", AT_EMPTY_PATH | AT_RECURSIVE,
                    &attributes, sizeof(attributes)) != 0) { close(tree); return -1; }
        copy = strdup(target);
        if (copy == NULL) { close(tree); return -1; }
    }
    if (pipe2(pipes, O_CLOEXEC) != 0) {
        if (tree >= 0) close(tree);
        free(copy);
        return -1;
    }
    child = fork();
    if (child == 0) {
        close(pipes[0]);
        result = guest_session_mount_worker(context, tree, target, directory) == 0
                     ? 0 : (errno == 0 ? EIO : errno);
        (void)write_all(pipes[1], &result, sizeof(result));
        _exit(result == 0 ? 0 : 1);
    }
    if (tree >= 0) close(tree);
    close(pipes[1]);
    if (child < 0) { close(pipes[0]); free(copy); return -1; }
    poller.fd = pipes[0];
    poller.events = POLLIN;
    poller.revents = 0;
    if (poll(&poller, 1, 5000) <= 0 || read(pipes[0], &result, sizeof(result)) != sizeof(result)) {
        result = ETIMEDOUT;
        (void)kill(child, SIGKILL);
        guest_session_broken = 1; /* the outcome of a timed-out mount is unknown */
    }
    close(pipes[0]);
    for (attempt = 0; attempt < 200; ++attempt) {
        pid_t reaped = waitpid(child, &status, WNOHANG);
        if (reaped == child) { confirmed = 1; break; }
        if (reaped < 0 && errno != EINTR) break;
        usleep(10000);
    }
    if (!confirmed || (result == 0 && (!WIFEXITED(status) || WEXITSTATUS(status) != 0))) {
        result = EBUSY;
        guest_session_broken = 1;
    }
    if (result != 0) {
        free(copy);
        errno = result;
        return -1;
    }
    free(context->mount_targets[slot]);
    context->mount_targets[slot] = copy;
    return 0;
}
