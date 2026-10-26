#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define OUTER_HEADER_LEN 44U
#define OUTER_MAX_PAYLOAD 65536U
#define OUTER_VERSION 1U
#define OUTER_GUEST_ATTACH 1U
#define OUTER_RESET 3U
#define OUTER_ACK 4U
#define OUTER_DATA 5U
#define OUTER_CREDIT 9U
#define OUTER_RECEIVE_WINDOW (1024U * 1024U)

#define APP_HEADER_LEN 24U
#define APP_VERSION 1U
#define APP_PING 1U
#define APP_EXEC 2U
#define APP_STOP 3U
#define APP_CANCEL 4U
#define APP_FEATURES 5U
#define APP_MAPS 6U
#define APP_UNMAP 7U
#define APP_READY 0x81U
#define APP_STDOUT 0x82U
#define APP_STDERR 0x83U
#define APP_EXIT 0x84U
#define APP_STOPPED 0x85U
#define APP_ERROR 0xffU

/*
 * Control features that a host can rely on, advertised in the answer to
 * FEATURES. The host refuses an image that lacks a feature it needs, so a
 * behavior that a host depends on needs a bit here and in the host's copy
 * (aci_edge_sandboxes, src/openvmm/protocol.rs). The init script of the image provides
 * FEATURE_WORKLOAD_ACCOUNT; the agent speaks for it because both ship in one
 * initramfs. An agent that predates FEATURES refuses the request as an
 * unsupported operation, which the host reads as no features. Bit 1 announced
 * bind mounts that nvx_map= kernel command-line tokens listed; it stays unused,
 * so hosts that still send those tokens refuse this image.
 */
#define FEATURE_CANCEL (1U << 0)
#define FEATURE_WORKLOAD_ACCOUNT (1U << 2)
#define FEATURE_EXEC_CGROUP (1U << 3)
#define FEATURE_EXEC_ENVIRONMENT (1U << 4)
#define FEATURE_EXEC_CWD (1U << 5)
#define FEATURE_HOST_MAPPING_TABLE (1U << 6)
/* APP_MAPS may append entries beyond the announced count once it is mounted. */
#define FEATURE_RUNTIME_MAPPINGS (1U << 7)
/*
 * The agent serves several workloads at the same time. Each exec request keeps
 * its own process group, cgroup leaf, output pipes and deadline, so cancelling
 * or timing out one execution leaves the others running. A host that does not
 * see this bit must keep sending one execution at a time.
 */
#define FEATURE_EXEC_SLOTS (1U << 8)
/*
 * An exec request may carry memMb, cpuPercent and pidsMax, which the agent
 * enforces on the execution's own cgroup leaf. A request that asks for a limit
 * the agent cannot enforce is refused instead of running unlimited.
 */
#define FEATURE_EXEC_LIMITS (1U << 9)

#define MAX_ARGUMENTS 64U
#define MAX_ARGUMENT_LEN 4096U
#define MAX_ENVIRONMENT 256U
#define EXEC_EXTENDED 1U
#define EXEC_CWD_PRESENT 1U
#define EXEC_ENVIRONMENT_PRESENT 2U
#define EXEC_INHERIT_DEFAULT_ENV 4U
/*
 * Extension 2 appends the execution's resource limits to the extended payload:
 * memory in MiB, CPU as a percentage of one core, and the largest number of
 * tasks. Zero means "no limit". A host asks for these only when the agent
 * advertises FEATURE_EXEC_LIMITS.
 */
#define EXEC_EXTENDED_V2 2U
/*
 * Set only in the configuration that a direct-mode child hands its launch
 * helper, never on the wire: the child already entered the working directory,
 * so the helper keeps it instead of looking the path up again.
 */
#define EXEC_CWD_ENTERED 0x8000U
#define MAX_OUTPUT_BYTES (1024U * 1024U)
#define OUTPUT_CHUNK_BYTES 32768U
/*
 * Executions the agent can supervise at once in direct mode. The host bounds
 * how many it actually starts; this is the agent's own capacity, and a request
 * beyond it is refused with "busy" before anything is forked.
 */
#define MAX_EXEC_SLOTS 8U
/* Bounds of the per-execution limits a host may ask for; a larger value is a
 * malformed request, not a hint. */
#define MAX_EXEC_MEMORY_MIB 4096U
#define MAX_EXEC_CPU_PERCENT 6400U
#define MAX_EXEC_PIDS 4096U
/* cgroup leaf of one execution, below the agent's cgroup root. Generous on
 * purpose: a test hierarchy can live under a long temporary directory. */
#define EXEC_CGROUP_NAME_BYTES 256U
/* CPU period the guest uses for every per-execution quota: 100 ms. */
#define CGROUP_CPU_PERIOD_US 100000U
/* Attempts one settle pass may spend before the agent serves control traffic again. */
#define SETTLE_ATTEMPTS_PER_PASS 8U
/* Total attempts before a cgroup that will not empty is reported as a failure. */
#define SETTLE_MAX_ATTEMPTS 200U
#define CONTAINER_BARRIER_ATTEMPTS 500U
#define PORTB_CONSOLE 0xe9
#define AGENT_STOPPED 1
#ifndef CGROUP_ROOT
#define CGROUP_ROOT "/sys/fs/cgroup"
#endif
#define EXEC_CGROUP CGROUP_ROOT "/nvx-exec"
#ifndef HOSTFS_DIR
#define HOSTFS_DIR "/run/nvx/hostfs"
#endif
#define HOSTFS_ROOT HOSTFS_DIR "/root"
#define MAPS_TOKEN "nvx_maps="
#define MAX_HOST_MAPPINGS 4096U
#define MAPS_HEADER_LEN 8U
#define MAP_ENTRY_HEADER_LEN 6U
#define MAP_READ_ONLY 1U
#define MAX_COMMAND_LINE 4096U
#define MAX_GUEST_PATH 4096U

struct outer_record {
    uint8_t type;
    uint8_t instance_id[16];
    uint64_t epoch;
    uint64_t sequence;
    uint32_t payload_len;
    uint8_t *payload;
};

struct control_session {
    int fd;
    uint8_t instance_id[16];
    uint64_t epoch;
    uint64_t guest_sequence;
    uint64_t host_sequence;
};

struct app_request {
    uint8_t kind;
    uint64_t request_id;
    int32_t status;
    uint32_t payload_len;
    const uint8_t *payload;
};

struct agent_config {
    const char *rootfs;
    const char *hostname;
    const char *uid;
    const char *gid;
    const char *user;
    const char *home;
    int direct;
};

struct exec_config {
    char *cwd;
    char **environment;
    uint16_t environment_count;
    int environment_present;
    int inherit_default_env;
    /*
     * Resource limits of this execution, from the extended payload. Zero means
     * "no limit"; a non-zero value is enforced on the execution's own cgroup
     * leaf, and the execution is refused if the guest cannot enforce it.
     */
    uint32_t mem_mb;
    uint32_t cpu_percent;
    uint32_t pids_max;
};

/*
 * Host mappings that nvx_maps= announces and APP_MAPS requests deliver. Until
 * every announced mapping is mounted, workloads are refused.
 */
#define MAX_RUNTIME_MAPPINGS 256U

struct host_mappings {
    uint32_t expected;
    uint32_t applied;
    int failed;
    /*
     * Targets of the mappings that APP_MAPS appended at run time and that
     * APP_UNMAP may still unmount; NULL marks a free slot. Mappings of the
     * announced table are never listed, so the host cannot unmount them.
     */
    char *runtime_targets[MAX_RUNTIME_MAPPINGS];
    /*
     * Sequence number of the next runtime APP_MAPS request. Runtime mappings do not
     * use the table's entry indices, so the table's bound does not limit how often
     * mappings are added and removed; only MAX_RUNTIME_MAPPINGS limits how many are
     * mounted at once.
     */
    uint32_t runtime_next;
};

#define LAUNCH_STAGE_CWD 1
#define LAUNCH_STAGE_SETUP 2

/* What a direct-mode child reports when it fails before it executes setpriv. */
struct launch_failure {
    int32_t stage;
    int32_t error;
};

/*
 * One execution the agent supervises. Each has its own process group, cgroup
 * leaf, output pipes, deadline and output budget, so the agent can move several
 * of them forward in one poll loop instead of blocking on a single child.
 */
#define SLOT_USED 0x0001U
#define SLOT_STDOUT_OPEN 0x0002U
#define SLOT_STDERR_OPEN 0x0004U
#define SLOT_EXITED 0x0008U
#define SLOT_CANCELLED 0x0010U
#define SLOT_TIMED_OUT 0x0020U
#define SLOT_OUTPUT_LIMITED 0x0040U
#define SLOT_STRAGGLERS_KILLED 0x0080U
/*
 * The host that could observe this execution is gone. Its output is drained
 * and its process killed, but nothing may be sent for it again: a reply for the
 * old epoch would be a protocol violation.
 */
#define SLOT_ABANDONED 0x0100U

struct exec_slot {
    uint32_t flags;
    uint64_t request_id;
    pid_t child;
    int stdout_fd;
    int stderr_fd;
    /* Direct mode: the child closes this pipe when it replaces itself with setpriv,
     * or writes why it could not. Read once the child has exited. */
    int launch_fd;
    /* Owned by the slot and released when the execution ends. */
    char **workload_argv;
    struct exec_config config;
    uint32_t timeout_ms;
    uint64_t started_ms;
    size_t output_bytes;
    int wait_status;
    int launch_report;
    struct launch_failure launch_failure;
    /* Empty when the execution has no cgroup (sandbox mode). */
    char cgroup[EXEC_CGROUP_NAME_BYTES];
    int cgroup_ready;
    /* Baselines belong to this leaf; the root has no memory.events file. */
    unsigned long long initial_oom;
    unsigned long long initial_oom_kill;
    int memory_events_ready;
    /* Attempts spent settling this execution's cgroup, so one pass stays bounded. */
    unsigned settle_attempts;
};

static uint16_t read_u16(const uint8_t *bytes)
{
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t read_u64(const uint8_t *bytes)
{
    uint64_t value = 0;
    unsigned int index;

    for (index = 0; index < 8; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8);
    }
    return value;
}

static void write_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
}

static void write_u32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void write_u64(uint8_t *bytes, uint64_t value)
{
    unsigned int index;

    for (index = 0; index < 8; ++index) {
        bytes[index] = (uint8_t)(value >> (index * 8));
    }
}

static int read_exact(int fd, void *buffer, size_t length)
{
    uint8_t *bytes = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = read(fd, bytes + offset, length - offset);
        if (count > 0) {
            offset += (size_t)count;
        } else if (count == 0) {
            return -1;
        } else if (errno != EINTR) {
            return -1;
        }
    }
    return 0;
}

static int write_all(int fd, const void *buffer, size_t length)
{
    const uint8_t *bytes = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = write(fd, bytes + offset, length - offset);
        if (count > 0) {
            offset += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static void portb_log(const char *message)
{
    int fd = open("/dev/port", O_WRONLY | O_CLOEXEC);

    if (fd < 0) {
        return;
    }
    while (*message != '\0') {
        if (pwrite(fd, message, 1, PORTB_CONSOLE) != 1) {
            break;
        }
        ++message;
    }
    close(fd);
}

static void portb_error(const char *stage, int status)
{
    char message[128];
    int length = snprintf(
        message,
        sizeof(message),
        "NVX-MANAGED-ERROR: stage=%s status=%d\n",
        stage,
        status);

    if (length > 0 && (size_t)length < sizeof(message)) {
        portb_log(message);
    }
}

static void free_outer_record(struct outer_record *record)
{
    free(record->payload);
    record->payload = NULL;
    record->payload_len = 0;
}

static int read_outer_record(int fd, struct outer_record *record)
{
    uint8_t header[OUTER_HEADER_LEN];

    memset(record, 0, sizeof(*record));
    if (read_exact(fd, header, sizeof(header)) != 0) {
        return -1;
    }
    if (memcmp(header, "NVXS", 4) != 0 || read_u16(header + 4) != OUTER_VERSION ||
        header[7] != 0) {
        return -1;
    }
    record->type = header[6];
    memcpy(record->instance_id, header + 8, sizeof(record->instance_id));
    record->epoch = read_u64(header + 24);
    record->sequence = read_u64(header + 32);
    record->payload_len = read_u32(header + 40);
    if (record->payload_len > OUTER_MAX_PAYLOAD) {
        return -1;
    }
    if (record->payload_len != 0) {
        record->payload = malloc(record->payload_len);
        if (record->payload == NULL ||
            read_exact(fd, record->payload, record->payload_len) != 0) {
            free_outer_record(record);
            return -1;
        }
    }
    return 0;
}

static int write_outer_record(
    int fd,
    uint8_t type,
    const uint8_t instance_id[16],
    uint64_t epoch,
    uint64_t sequence,
    const void *payload,
    uint32_t payload_len)
{
    uint8_t header[OUTER_HEADER_LEN] = {0};

    if (payload_len > OUTER_MAX_PAYLOAD) {
        return -1;
    }
    memcpy(header, "NVXS", 4);
    write_u16(header + 4, OUTER_VERSION);
    header[6] = type;
    memcpy(header + 8, instance_id, 16);
    write_u64(header + 24, epoch);
    write_u64(header + 32, sequence);
    write_u32(header + 40, payload_len);
    if (write_all(fd, header, sizeof(header)) != 0) {
        return -1;
    }
    return payload_len == 0 || write_all(fd, payload, payload_len) == 0 ? 0 : -1;
}

/* Accepts a /-separated path without empty, "." (unless alone), or ".." components. */
static int safe_path(const char *path, int absolute)
{
    const char *component = path;

    if (absolute) {
        if (path[0] != '/') {
            return 0;
        }
        component = path + 1;
        if (*component == '\0') {
            return 0;
        }
    } else if (strcmp(path, ".") == 0) {
        return 1;
    }
    while (*component != '\0') {
        const char *end = strchr(component, '/');
        size_t length = end == NULL ? strlen(component) : (size_t)(end - component);

        if (length == 0 || (length == 1 && component[0] == '.') ||
            (length == 2 && component[0] == '.' && component[1] == '.')) {
            return 0;
        }
        component += length;
        if (*component == '/') {
            ++component;
            if (*component == '\0') {
                return 0;
            }
        }
    }
    return 1;
}

/* Creates every missing directory of `path` up to, and optionally including, its last component. */
static int make_directories(const char *path, int include_last)
{
    char buffer[MAX_GUEST_PATH];
    size_t index;
    size_t length = strlen(path);

    if (length >= sizeof(buffer)) {
        return -1;
    }
    memcpy(buffer, path, length + 1);
    for (index = 1; index <= length; ++index) {
        if (buffer[index] == '/' || (buffer[index] == '\0' && include_last)) {
            char saved = buffer[index];

            buffer[index] = '\0';
            if (mkdir(buffer, 0755) != 0 && errno != EEXIST) {
                return -1;
            }
            buffer[index] = saved;
        }
    }
    return 0;
}

/*
 * Reads the number of host mappings that nvx_maps=COUNT announces into
 * `count`, or 0 without the token. Tokens are split in place. Older hosts
 * listed their mappings in nvx_map= tokens, which are ignored.
 */
static int parse_host_mapping_count(char *command_line, uint32_t *count)
{
    char *token;
    char *cursor;
    int found = 0;

    *count = 0;
    for (token = strtok_r(command_line, " \t\n", &cursor); token != NULL;
         token = strtok_r(NULL, " \t\n", &cursor)) {
        const char *digit = token + strlen(MAPS_TOKEN);
        uint32_t value = 0;

        if (strncmp(token, MAPS_TOKEN, strlen(MAPS_TOKEN)) != 0) {
            continue;
        }
        if (found || *digit == '\0') {
            errno = EINVAL;
            return -1;
        }
        for (; *digit != '\0'; ++digit) {
            if (*digit < '0' || *digit > '9' || value > MAX_HOST_MAPPINGS) {
                errno = EINVAL;
                return -1;
            }
            value = value * 10U + (uint32_t)(*digit - '0');
        }
        if (value == 0 || value > MAX_HOST_MAPPINGS) {
            errno = EINVAL;
            return -1;
        }
        *count = value;
        found = 1;
    }
    return 0;
}

/*
 * Reads the number of announced host mappings and, while the host's export is
 * mounted at HOSTFS_ROOT, makes its parent a directory that only root may
 * enter, so workloads reach mapped paths only through the bind mounts. The
 * announced mappings need that export.
 */
static int prepare_host_mappings(struct host_mappings *mappings)
{
    char command_line[MAX_COMMAND_LINE];
    struct stat parent;
    struct stat export;
    ssize_t count;
    int mounted;
    int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        return -1;
    }
    count = read(fd, command_line, sizeof(command_line) - 1);
    close(fd);
    if (count < 0) {
        return -1;
    }
    command_line[count] = '\0';
    if (parse_host_mapping_count(command_line, &mappings->expected) != 0) {
        return -1;
    }
    mounted = stat(HOSTFS_DIR, &parent) == 0 && stat(HOSTFS_ROOT, &export) == 0 &&
              parent.st_dev != export.st_dev;
    if (mounted && (chown(HOSTFS_DIR, 0, 0) != 0 || chmod(HOSTFS_DIR, 0700) != 0)) {
        return -1;
    }
    if (mappings->expected != 0 && !mounted) {
        errno = ENOENT;
        return -1;
    }
    return 0;
}

/*
 * Bind-mounts SOURCE, a path relative to the export, at the guest path TARGET,
 * read-only or read-write, without set-user-ID programs or device nodes.
 */
static int apply_host_mapping(const char *source, const char *target, int read_only)
{
    char host[MAX_GUEST_PATH + sizeof(HOSTFS_ROOT) + 1];
    struct stat status;
    unsigned long flags = MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV;

    if (read_only) {
        flags |= MS_RDONLY;
    }
    snprintf(host, sizeof(host), "%s/%s", HOSTFS_ROOT, source);
    if (lstat(host, &status) != 0) {
        return -1;
    }
    if (S_ISDIR(status.st_mode)) {
        if (make_directories(target, 1) != 0) {
            return -1;
        }
    } else if (S_ISREG(status.st_mode)) {
        struct stat existing;

        if (make_directories(target, 0) != 0) {
            return -1;
        }
        /*
         * An existing target may lie inside an earlier read-only bind, where
         * even O_CREAT with write access fails, so only a missing one is made.
         */
        if (lstat(target, &existing) != 0) {
            int file;

            if (errno != ENOENT) {
                return -1;
            }
            file = open(target, O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
            if (file < 0) {
                return -1;
            }
            close(file);
        } else if (!S_ISREG(existing.st_mode)) {
            errno = EINVAL;
            return -1;
        }
    } else {
        errno = EINVAL;
        return -1;
    }
    if (mount(host, target, NULL, MS_BIND, NULL) != 0 ||
        mount(NULL, target, NULL, flags, NULL) != 0) {
        return -1;
    }
    return 0;
}

/*
 * Decodes the APP_MAPS entry at `*offset` and advances past it: 16-bit flags,
 * source length, and target length, then the source, a relative path of the
 * export, and the target, an absolute guest path.
 */
static int decode_host_mapping(
    const uint8_t *payload,
    uint32_t payload_len,
    uint32_t *offset,
    char *source,
    char *target,
    int *read_only)
{
    uint16_t flags;
    uint16_t source_len;
    uint16_t target_len;

    if (payload_len - *offset < MAP_ENTRY_HEADER_LEN) {
        return -1;
    }
    flags = read_u16(payload + *offset);
    source_len = read_u16(payload + *offset + 2);
    target_len = read_u16(payload + *offset + 4);
    *offset += MAP_ENTRY_HEADER_LEN;
    if ((flags & ~MAP_READ_ONLY) != 0 || source_len == 0 || target_len == 0 ||
        source_len >= MAX_GUEST_PATH || target_len >= MAX_GUEST_PATH ||
        payload_len - *offset < (uint32_t)source_len + target_len) {
        return -1;
    }
    memcpy(source, payload + *offset, source_len);
    source[source_len] = '\0';
    *offset += source_len;
    memcpy(target, payload + *offset, target_len);
    target[target_len] = '\0';
    *offset += target_len;
    if (strlen(source) != source_len || strlen(target) != target_len ||
        strcmp(source, ".") == 0 || !safe_path(source, 0) || !safe_path(target, 1)) {
        return -1;
    }
    *read_only = (flags & MAP_READ_ONLY) != 0;
    return 0;
}

static int send_guest_attach(int fd)
{
    const uint8_t zero_instance[16] = {0};

    return write_outer_record(
        fd, OUTER_GUEST_ATTACH, zero_instance, 0, 0, NULL, 0);
}

static int acknowledge_reset(
    struct control_session *session,
    const struct outer_record *record)
{
    uint8_t credit[4];

    if (record->type != OUTER_RESET || record->payload_len != 0 ||
        record->epoch == 0) {
        return -1;
    }
    memcpy(session->instance_id, record->instance_id, 16);
    session->epoch = record->epoch;
    session->guest_sequence = 0;
    session->host_sequence = record->sequence + 1;
    write_u32(credit, OUTER_RECEIVE_WINDOW);
    if (write_outer_record(
            session->fd,
            OUTER_ACK,
            session->instance_id,
            session->epoch,
            session->guest_sequence,
            credit,
            sizeof(credit)) != 0) {
        return -1;
    }
    session->guest_sequence = 1;
    return 0;
}

static int send_guest_record(
    struct control_session *session,
    uint8_t type,
    const void *payload,
    uint32_t payload_len)
{
    if (write_outer_record(
            session->fd,
            type,
            session->instance_id,
            session->epoch,
            session->guest_sequence,
            payload,
            payload_len) != 0) {
        return -1;
    }
    ++session->guest_sequence;
    return 0;
}

static int send_credit(struct control_session *session, uint32_t bytes)
{
    uint8_t payload[4];

    if (bytes == 0) {
        return 0;
    }
    write_u32(payload, bytes);
    return send_guest_record(session, OUTER_CREDIT, payload, sizeof(payload));
}

static int send_app_frame(
    struct control_session *session,
    uint8_t kind,
    uint64_t request_id,
    int32_t status,
    const void *payload,
    uint32_t payload_len)
{
    uint8_t *frame;
    uint32_t frame_len;
    int result;

    if (payload_len > OUTER_MAX_PAYLOAD - APP_HEADER_LEN) {
        return -1;
    }
    frame_len = APP_HEADER_LEN + payload_len;
    frame = malloc(frame_len);
    if (frame == NULL) {
        return -1;
    }
    memset(frame, 0, APP_HEADER_LEN);
    memcpy(frame, "NVXC", 4);
    frame[4] = APP_VERSION;
    frame[5] = kind;
    write_u64(frame + 8, request_id);
    write_u32(frame + 16, (uint32_t)status);
    write_u32(frame + 20, payload_len);
    if (payload_len != 0) {
        memcpy(frame + APP_HEADER_LEN, payload, payload_len);
    }
    result = send_guest_record(session, OUTER_DATA, frame, frame_len);
    free(frame);
    return result;
}

static int parse_app_request(
    const uint8_t *payload,
    uint32_t payload_len,
    struct app_request *request)
{
    uint32_t declared_len;

    if (payload_len < APP_HEADER_LEN || memcmp(payload, "NVXC", 4) != 0 ||
        payload[4] != APP_VERSION || read_u16(payload + 6) != 0) {
        return -1;
    }
    declared_len = read_u32(payload + 20);
    if (declared_len != payload_len - APP_HEADER_LEN) {
        return -1;
    }
    request->kind = payload[5];
    request->request_id = read_u64(payload + 8);
    request->status = (int32_t)read_u32(payload + 16);
    request->payload_len = declared_len;
    request->payload = payload + APP_HEADER_LEN;
    return request->request_id != 0 && request->status == 0 ? 0 : -1;
}

static int send_app_error(
    struct control_session *session,
    uint64_t request_id,
    int32_t status,
    const char *category)
{
    return send_app_frame(
        session,
        APP_ERROR,
        request_id,
        status,
        category,
        (uint32_t)strlen(category));
}

static uint64_t monotonic_milliseconds(void)
{
    struct timespec value;

    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        return 0;
    }
    return (uint64_t)value.tv_sec * 1000U + (uint64_t)value.tv_nsec / 1000000U;
}

static int open_control_tty(const char *path)
{
    const struct timespec delay = {
        .tv_sec = 0,
        .tv_nsec = 50U * 1000U * 1000U,
    };
    unsigned int attempt;

    for (attempt = 0; attempt < 600; ++attempt) {
        int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd >= 0) {
            return fd;
        }
        if (errno != ENOENT && errno != ENXIO && errno != ENODEV && errno != EIO) {
            return -1;
        }
        nanosleep(&delay, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int configure_control_tty(int fd)
{
    struct termios settings;

    if (tcgetattr(fd, &settings) != 0) {
        return -1;
    }
    cfmakeraw(&settings);
    settings.c_cflag |= CLOCAL;
    return tcsetattr(fd, TCSANOW, &settings);
}

static int make_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);

    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 ? 0 : -1;
}

static int write_pid_to_cgroup(pid_t pid)
{
    char buffer[32];
    int fd;
    int length;

    fd = open("/sys/fs/cgroup/container/cgroup.procs", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    length = snprintf(buffer, sizeof(buffer), "%ld\n", (long)pid);
    if (length <= 0 || (size_t)length >= sizeof(buffer) ||
        write_all(fd, buffer, (size_t)length) != 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static int write_container_barrier(int fd)
{
    struct sigaction ignored = {0};
    struct sigaction previous;
    int result;
    int status;

    ignored.sa_handler = SIG_IGN;
    if (sigemptyset(&ignored.sa_mask) != 0 ||
        sigaction(SIGPIPE, &ignored, &previous) != 0) {
        return -1;
    }
    result = write_all(fd, "start\n", 6);
    status = errno;
    if (sigaction(SIGPIPE, &previous, NULL) != 0) {
        return -1;
    }
    if (result != 0) {
        errno = status;
    }
    return result;
}

/* Returns 0 after writing, 1 for an unreaped child exit, or -1 on failure. */
static int release_container_barrier(const char *path, pid_t child)
{
    unsigned int attempt;

    for (attempt = 0; attempt < CONTAINER_BARRIER_ATTEMPTS; ++attempt) {
        int fd = open(path, O_WRONLY | O_CLOEXEC | O_NONBLOCK);

        if (fd >= 0) {
            int result = write_container_barrier(fd);

            close(fd);
            return result;
        }
        if (errno != ENXIO && errno != EINTR) {
            return -1;
        }
        if (child > 0) {
            siginfo_t information = {0};

            if (waitid(
                    P_PID,
                    (id_t)child,
                    &information,
                    WEXITED | WNOHANG | WNOWAIT) != 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            if (information.si_pid == child) {
                return 1;
            }
        }
        {
            const struct timespec delay = {.tv_nsec = 10000000L};

            nanosleep(&delay, NULL);
        }
    }
    errno = ETIMEDOUT;
    return -1;
}

/*
 * Enables one controller in the root cgroup, so every leaf below it can enforce
 * it. The kernel refuses a controller it does not offer, which is how a caller
 * learns that a limit it asked for cannot be enforced in this guest.
 */
static int enable_controller(const char *controller)
{
    char command[32];
    int fd;
    int result;
    int status;
    int length = snprintf(command, sizeof(command), "+%s", controller);

    if (length <= 0 || (size_t)length >= sizeof(command)) {
        errno = EINVAL;
        return -1;
    }
    /*
     * cgroupfs ignores the file position of a write, so O_APPEND changes
     * nothing there; it keeps the sequence visible when the file is a regular
     * one, as the unit tests' stand-in for the hierarchy is.
     */
    fd = open(CGROUP_ROOT "/cgroup.subtree_control", O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    result = write_all(fd, command, (size_t)length);
    status = errno;
    if (close(fd) != 0 && result == 0) {
        return -1;
    }
    if (result != 0) {
        errno = status;
    }
    return result;
}

/*
 * Direct-mode workloads run in the guest's own root file system, contained by a
 * cgroup leaf that every process of the execution inherits, whatever session or
 * process group it moves to. Killing the leaf ends all of them, and its pids
 * controller counts each of them until PID 1 reaps it.
 *
 * `pids` is always enabled: it is what proves an execution has really finished.
 * `memory` and `cpu` are enabled only when an execution asks for them, so a
 * guest that offers neither still runs unrestricted executions.
 */
static int prepare_cgroup_root(int need_memory, int need_cpu)
{
    struct stat status;

    if (stat(CGROUP_ROOT "/cgroup.procs", &status) != 0) {
        if (mkdir(CGROUP_ROOT, 0755) != 0 && errno != EEXIST) {
            return -1;
        }
        if (mount("cgroup2", CGROUP_ROOT, "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) !=
            0) {
            return -1;
        }
    }
    if (enable_controller("pids") != 0) {
        return -1;
    }
    if (need_memory && enable_controller("memory") != 0) {
        return -1;
    }
    if (need_cpu && enable_controller("cpu") != 0) {
        return -1;
    }
    return 0;
}

/* Leaf the next forked child joins; the child inherits it across fork(). */
static const char *g_child_cgroup;

static int join_cgroup(const char *path)
{
    char buffer[32];
    char procs[EXEC_CGROUP_NAME_BYTES + 16U];
    int fd;
    int length;
    int result;
    int written = snprintf(procs, sizeof(procs), "%s/cgroup.procs", path);

    if (written <= 0 || (size_t)written >= sizeof(procs)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    /*
     * O_CREAT is a no-op on cgroupfs, which creates a leaf's files with the
     * leaf; it lets the unit tests model a leaf with a plain directory.
     */
    fd = open(procs, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) {
        return -1;
    }
    length = snprintf(buffer, sizeof(buffer), "%ld\n", (long)getpid());
    result = length > 0 && (size_t)length < sizeof(buffer)
                 ? write_all(fd, buffer, (size_t)length)
                 : -1;
    close(fd);
    return result;
}

/* Writes one file of a cgroup leaf. */
static int write_cgroup_file(const char *path, const char *name, const char *value)
{
    char file[EXEC_CGROUP_NAME_BYTES + 32U];
    int fd;
    int result;
    int status;
    int written = snprintf(file, sizeof(file), "%s/%s", path, name);

    if (written <= 0 || (size_t)written >= sizeof(file)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    /* O_CREAT is a no-op on cgroupfs; see join_cgroup(). */
    fd = open(file, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) {
        return -1;
    }
    result = write_all(fd, value, strlen(value));
    status = errno;
    if (close(fd) != 0 && result == 0) {
        return -1;
    }
    if (result != 0) {
        errno = status;
    }
    return result;
}

/* Read both counters together. Unavailable accounting must not fabricate OOM. */
static int read_memory_events(const char *path, unsigned long long *oom,
    unsigned long long *oom_kill)
{
    char file[EXEC_CGROUP_NAME_BYTES + 32U];
    char buffer[1024];
    const char *cursor;
    unsigned found = 0;
    int written;
    int fd;
    ssize_t got;

    written = snprintf(file, sizeof(file), "%s/memory.events", path);
    if (written <= 0 || (size_t)written >= sizeof(file)) {
        return -1;
    }
    fd = open(file, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    do {
        got = read(fd, buffer, sizeof(buffer) - 1U);
    } while (got < 0 && errno == EINTR);
    close(fd);
    if (got <= 0 || (size_t)got == sizeof(buffer) - 1U) {
        return -1;
    }
    buffer[got] = '\0';
    cursor = buffer;
    while (cursor != NULL) {
        char key[64];
        unsigned long long value;

        if (sscanf(cursor, "%63s %llu", key, &value) == 2) {
            if (strcmp(key, "oom") == 0) {
                *oom = value;
                found |= 1U;
            } else if (strcmp(key, "oom_kill") == 0) {
                *oom_kill = value;
                found |= 2U;
            }
        }
        cursor = strchr(cursor, '\n');
        if (cursor != NULL) {
            ++cursor;
        }
    }
    return found == 3U ? 0 : -1;
}

/*
 * oom_kill counts victims of both local and global OOM. The leaf's oom counter
 * counts hitting that leaf's own memory limit. These exec leaves sit directly
 * under the root (no ancestor memory limits), so a victim without a local oom
 * event was killed by VM-wide pressure. Never use unrelated executions' counters.
 */
static const char *slot_oom_category(const struct exec_slot *slot)
{
    unsigned long long oom = 0;
    unsigned long long oom_kill = 0;

    if (!slot->cgroup_ready || !slot->memory_events_ready ||
        (WIFSIGNALED(slot->wait_status) && WTERMSIG(slot->wait_status) != SIGKILL) ||
        read_memory_events(slot->cgroup, &oom, &oom_kill) != 0 ||
        oom_kill <= slot->initial_oom_kill) {
        return NULL;
    }
    return oom > slot->initial_oom ? "oom" : "vm-oom";
}

/* Defined with the rest of the pids-controller helpers below. */
static int cgroup_has_tasks(const char *path);

/*
 * Creates the leaf of one execution and applies its limits before the child can
 * join it, so a workload never runs without what the caller asked for. A limit
 * the guest cannot enforce fails here, and the execution is refused instead of
 * running unlimited.
 */
static int create_slot_cgroup(struct exec_slot *slot, uint32_t memory_mib,
    uint32_t cpu_percent, uint32_t pids_max)
{
    char value[64];
    int written;

    written = snprintf(slot->cgroup, sizeof(slot->cgroup), CGROUP_ROOT "/nvx-exec-%llu",
        (unsigned long long)slot->request_id);
    if (written <= 0 || (size_t)written >= sizeof(slot->cgroup)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (mkdir(slot->cgroup, 0755) != 0) {
        /*
         * A leaf that is already there is reusable only when it is empty: the
         * request id must not inherit processes from an earlier execution.
         */
        int remaining;

        if (errno != EEXIST) {
            return -1;
        }
        remaining = cgroup_has_tasks(slot->cgroup);
        if (remaining != 0) {
            errno = EEXIST;
            return -1;
        }
    }
    if (memory_mib != 0) {
        written = snprintf(value, sizeof(value), "%llu",
            (unsigned long long)memory_mib * 1024ULL * 1024ULL);
        if (written <= 0 || (size_t)written >= sizeof(value) ||
            write_cgroup_file(slot->cgroup, "memory.max", value) != 0) {
            return -1;
        }
    }
    /* Global OOM must also retire a whole execution, not just its allocating child. */
    if (write_cgroup_file(slot->cgroup, "memory.oom.group", "1") != 0) {
        return -1;
    }
    if (cpu_percent != 0) {
        unsigned long long quota =
            (unsigned long long)cpu_percent * CGROUP_CPU_PERIOD_US / 100ULL;

        written = snprintf(value, sizeof(value), "%llu %u", quota, CGROUP_CPU_PERIOD_US);
        if (written <= 0 || (size_t)written >= sizeof(value) ||
            write_cgroup_file(slot->cgroup, "cpu.max", value) != 0) {
            return -1;
        }
    }
    if (pids_max != 0) {
        written = snprintf(value, sizeof(value), "%u", pids_max);
        if (written <= 0 || (size_t)written >= sizeof(value) ||
            write_cgroup_file(slot->cgroup, "pids.max", value) != 0) {
            return -1;
        }
    }
    slot->cgroup_ready = 1;
    slot->memory_events_ready = read_memory_events(slot->cgroup,
        &slot->initial_oom, &slot->initial_oom_kill) == 0;
    return 0;
}

static int kill_cgroup(const char *path)
{
    int result = write_cgroup_file(path, "cgroup.kill", "1");

    if (result != 0) {
        int status = errno;

        portb_error("exec-cgroup-kill", status);
        errno = status;
    }
    return result;
}

/*
 * Returns 1 if the pids controller still charges a task to the leaf, 0 if it
 * charges none, or -1. A task stays charged until it is reaped, while
 * cgroup.events stops counting a killed process as populated before the
 * process even becomes a zombie.
 */
static int cgroup_has_tasks(const char *path)
{
    char buffer[32];
    char file[EXEC_CGROUP_NAME_BYTES + 32U];
    size_t length = 0;
    size_t index;
    int fd;
    int written = snprintf(file, sizeof(file), "%s/pids.current", path);

    if (written <= 0 || (size_t)written >= sizeof(file)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open(file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    for (;;) {
        ssize_t count = read(fd, buffer + length, sizeof(buffer) - length);

        if (count > 0) {
            length += (size_t)count;
            if (length < sizeof(buffer)) {
                continue;
            }
            errno = EOVERFLOW;
        } else if (count == 0) {
            break;
        } else if (errno == EINTR) {
            continue;
        }
        {
            int status = errno;

            close(fd);
            errno = status;
            return -1;
        }
    }
    if (close(fd) != 0) {
        return -1;
    }
    /* A decimal count without sign or leading zeros, then a newline. */
    if (length < 2 || buffer[length - 1] != '\n' || (buffer[0] == '0' && length != 2)) {
        errno = EPROTO;
        return -1;
    }
    for (index = 0; index + 1 < length; ++index) {
        if (buffer[index] < '0' || buffer[index] > '9') {
            errno = EPROTO;
            return -1;
        }
    }
    return buffer[0] != '0';
}

/*
 * Reaps exited children without blocking. The agent runs as PID 1, so besides
 * the direct child of each execution it inherits every orphaned workload
 * process. A reaped child is matched to its slot, which is how the scheduler
 * learns that an execution has exited.
 */
static void reap_children(struct exec_slot *slots, size_t count)
{
    for (;;) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        size_t index;

        if (pid < 0 && errno == EINTR) {
            continue;
        }
        if (pid <= 0) {
            return;
        }
        for (index = 0; index < count; ++index) {
            struct exec_slot *slot = &slots[index];

            if ((slot->flags & SLOT_USED) != 0 && slot->child == pid &&
                (slot->flags & SLOT_EXITED) == 0) {
                slot->flags |= SLOT_EXITED;
                slot->wait_status = status;
            }
        }
    }
}

/*
 * Kills what is left of one execution and waits until it is gone: every process
 * the execution started has exited and been reaped, so the next execution
 * cannot find any of them in /proc, and its leaf can be removed.
 *
 * The wait is bounded per call: an execution that takes long to die must not
 * keep the agent from answering control traffic, so the caller passes its
 * attempt counter in and comes back on the next loop iteration. Returns 0 when
 * the cgroup is empty, 1 when it is still settling, or -1 on failure.
 */
static int settle_cgroup(const char *path, struct exec_slot *slots, size_t count,
    unsigned *attempts)
{
    const struct timespec delay = {
        .tv_sec = 0,
        .tv_nsec = 10U * 1000U * 1000U,
    };
    unsigned pass;

    if (*attempts == 0 && kill_cgroup(path) != 0) {
        return -1;
    }
    for (pass = 0; pass < SETTLE_ATTEMPTS_PER_PASS; ++pass, ++*attempts) {
        int remaining;

        reap_children(slots, count);
        remaining = cgroup_has_tasks(path);
        if (remaining < 0) {
            return -1;
        }
        if (remaining == 0) {
            return 0;
        }
        if (*attempts >= SETTLE_MAX_ATTEMPTS) {
            errno = ETIMEDOUT;
            return -1;
        }
        nanosleep(&delay, NULL);
    }
    return 1;
}

/* Removes an empty leaf. A leaf that still holds tasks stays, and is logged. */
static void remove_cgroup(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return;
    }
    if (rmdir(path) != 0 && errno != ENOENT) {
        portb_error("exec-cgroup-remove", errno);
    }
}

/* Parses a workload user or group ID: decimal, neither root nor the "unchanged" value -1. */
static int parse_workload_id(const char *text, uint32_t *id)
{
    char *end = NULL;
    unsigned long value;

    if (text[0] < '0' || text[0] > '9') {
        errno = EINVAL;
        return -1;
    }
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value == 0 || value >= UINT32_MAX) {
        errno = EINVAL;
        return -1;
    }
    *id = (uint32_t)value;
    return 0;
}

/* Tells the agent why a direct-mode child cannot launch its workload, then exits. */
static void report_launch_failure(int launch_fd, int32_t stage, int error)
{
    struct launch_failure failure = {.stage = stage, .error = error};

    (void)write_all(launch_fd, &failure, sizeof(failure));
    _exit(125);
}

/*
 * Enters the working directory with the workload's IDs, no supplementary
 * groups, and no effective capabilities, as setpriv will run the workload, so
 * a directory that the workload cannot search is refused before anything
 * runs, instead of failing in the launch helper with an exit status that the
 * workload could also return. The real and saved IDs stay root, so the child
 * regains root for setpriv afterwards. setpriv and the launch helper inherit
 * the directory instead of looking its path up again, so the workload starts
 * in the directory that was checked even if the path is renamed, replaced, or
 * retargeted in the meantime.
 */
static void enter_workload_directory(
    const struct agent_config *config,
    const char *directory,
    int launch_fd)
{
    uint32_t uid;
    uint32_t gid;

    if (parse_workload_id(config->uid, &uid) != 0 ||
        parse_workload_id(config->gid, &gid) != 0 || setgroups(0, NULL) != 0 ||
        setegid((gid_t)gid) != 0 || seteuid((uid_t)uid) != 0) {
        report_launch_failure(launch_fd, LAUNCH_STAGE_SETUP, errno);
    }
    if (chdir(directory) != 0) {
        report_launch_failure(launch_fd, LAUNCH_STAGE_CWD, errno);
    }
    if (seteuid(0) != 0 || setegid(0) != 0) {
        report_launch_failure(launch_fd, LAUNCH_STAGE_SETUP, errno);
    }
}

/*
 * Points PWD at the working directory, so a shell reports it as the caller
 * named it, symbolic links included. A path with empty, ".", or ".."
 * components is replaced by the directory's physical path.
 */
static int export_working_directory(const char *directory)
{
    char physical[MAX_GUEST_PATH];

    if (strcmp(directory, "/") == 0 || safe_path(directory, 1)) {
        return setenv("PWD", directory, 1);
    }
    if (getcwd(physical, sizeof(physical)) == NULL) {
        return -1;
    }
    return setenv("PWD", physical, 1);
}

static void exec_direct(
    const struct agent_config *config,
    const char *config_fd,
    char *const workload_argv[])
{
    char *arguments[MAX_ARGUMENTS + 20];
    size_t index = 0;
    size_t workload_index = 0;

    if (g_child_cgroup != NULL && join_cgroup(g_child_cgroup) != 0) {
        _exit(125);
    }
    if (setenv("HOME", config->home, 1) != 0 ||
        setenv("USER", config->user, 1) != 0 ||
        setenv("LOGNAME", config->user, 1) != 0) {
        dprintf(
            STDERR_FILENO,
            "nvx-managed-agent: cannot configure workload environment: %s\n",
            strerror(errno));
        _exit(125);
    }
    arguments[index++] = "setpriv";
    arguments[index++] = "--reuid";
    arguments[index++] = (char *)config->uid;
    arguments[index++] = "--regid";
    arguments[index++] = (char *)config->gid;
    arguments[index++] = "--clear-groups";
    arguments[index++] = "--no-new-privs";
    arguments[index++] = "--bounding-set=-all";
    arguments[index++] = "--inh-caps=-all";
    arguments[index++] = "--ambient-caps=-all";
    arguments[index++] = "/sbin/nvx-managed-agent";
    arguments[index++] = "--exec-config-fd";
    arguments[index++] = (char *)config_fd;
    arguments[index++] = "--";
    while (workload_argv[workload_index] != NULL && index + 1 < MAX_ARGUMENTS + 20) {
        arguments[index++] = workload_argv[workload_index++];
    }
    arguments[index] = NULL;
    execvp("setpriv", arguments);
    _exit(125);
}

static void exec_sandbox(
    const struct agent_config *config,
    const char *barrier,
    const char *config_fd,
    char *const workload_argv[])
{
    char *arguments[MAX_ARGUMENTS + 10];
    size_t index = 0;
    size_t workload_index = 0;

    arguments[index++] = "/sbin/nvx-container-launch";
    arguments[index++] = (char *)barrier;
    arguments[index++] = (char *)config->rootfs;
    arguments[index++] = (char *)config->hostname;
    arguments[index++] = (char *)config->uid;
    arguments[index++] = (char *)config->gid;
    arguments[index++] = (char *)config->user;
    arguments[index++] = (char *)config->home;
    if (setenv("NVX_EXEC_CONFIG_FD", config_fd, 1) != 0) {
        dprintf(
            STDERR_FILENO,
            "nvx-managed-agent: cannot export execution configuration: %s\n",
            strerror(errno));
        _exit(125);
    }
    while (workload_argv[workload_index] != NULL && index + 1 < MAX_ARGUMENTS + 10) {
        arguments[index++] = workload_argv[workload_index++];
    }
    arguments[index] = NULL;
    execv(arguments[0], arguments);
    _exit(125);
}

static int decode_exec_payload(
    const uint8_t *payload,
    uint32_t payload_len,
    uint32_t *timeout_ms,
    char ***workload_argv,
    struct exec_config *config)
{
    uint16_t argc;
    uint16_t extension;
    uint16_t flags = 0;
    uint16_t environment_count = 0;
    uint32_t cwd_len = 0;
    uint32_t offset = 8;
    char **arguments;
    uint16_t index;

    memset(config, 0, sizeof(*config));
    if (payload_len < 8) {
        return -1;
    }
    *timeout_ms = read_u32(payload);
    argc = read_u16(payload + 4);
    extension = read_u16(payload + 6);
    if (argc == 0 || argc > MAX_ARGUMENTS) {
        return -1;
    }
    if (extension == EXEC_EXTENDED || extension == EXEC_EXTENDED_V2) {
        uint32_t header_len = extension == EXEC_EXTENDED_V2 ? 28U : 16U;

        if (payload_len < header_len) {
            return -1;
        }
        flags = read_u16(payload + 8);
        environment_count = read_u16(payload + 10);
        cwd_len = read_u32(payload + 12);
        if (extension == EXEC_EXTENDED_V2) {
            config->mem_mb = read_u32(payload + 16);
            config->cpu_percent = read_u32(payload + 20);
            config->pids_max = read_u32(payload + 24);
        }
        offset = header_len;
        if ((flags &
             ~(EXEC_CWD_PRESENT | EXEC_ENVIRONMENT_PRESENT |
               EXEC_INHERIT_DEFAULT_ENV)) != 0 ||
            ((flags & EXEC_CWD_PRESENT) == 0 && cwd_len != 0) ||
            ((flags & EXEC_CWD_PRESENT) != 0 &&
             (cwd_len == 0 || cwd_len > MAX_ARGUMENT_LEN)) ||
            ((flags & EXEC_ENVIRONMENT_PRESENT) == 0 &&
             (environment_count != 0 ||
              (flags & EXEC_INHERIT_DEFAULT_ENV) != 0)) ||
            environment_count > MAX_ENVIRONMENT ||
            config->mem_mb > MAX_EXEC_MEMORY_MIB ||
            config->cpu_percent > MAX_EXEC_CPU_PERCENT ||
            config->pids_max > MAX_EXEC_PIDS) {
            return -1;
        }
    } else if (extension != 0) {
        return -1;
    }
    arguments = calloc((size_t)argc + 1, sizeof(*arguments));
    if (arguments == NULL) {
        return -1;
    }
    for (index = 0; index < argc; ++index) {
        uint32_t length;

        if (offset > payload_len || payload_len - offset < 4) {
            goto fail;
        }
        length = read_u32(payload + offset);
        offset += 4;
        if (length == 0 || length > MAX_ARGUMENT_LEN || length > payload_len - offset ||
            memchr(payload + offset, '\0', length) != NULL) {
            goto fail;
        }
        arguments[index] = malloc((size_t)length + 1);
        if (arguments[index] == NULL) {
            goto fail;
        }
        memcpy(arguments[index], payload + offset, length);
        arguments[index][length] = '\0';
        offset += length;
    }
    if (arguments[0][0] != '/' ||
        (extension == 0 && offset != payload_len)) {
        goto fail;
    }
    if (extension != 0) {
        if (cwd_len != 0) {
            if (cwd_len > payload_len - offset ||
                memchr(payload + offset, '\0', cwd_len) != NULL ||
                payload[offset] != '/') {
                goto fail;
            }
            config->cwd = malloc((size_t)cwd_len + 1);
            if (config->cwd == NULL) {
                goto fail;
            }
            memcpy(config->cwd, payload + offset, cwd_len);
            config->cwd[cwd_len] = '\0';
            offset += cwd_len;
        }
        if ((flags & EXEC_ENVIRONMENT_PRESENT) != 0) {
            config->environment = calloc(
                (size_t)environment_count + 1, sizeof(*config->environment));
            if (config->environment == NULL) {
                goto fail;
            }
            config->environment_present = 1;
            config->inherit_default_env =
                (flags & EXEC_INHERIT_DEFAULT_ENV) != 0;
            config->environment_count = environment_count;
            for (index = 0; index < environment_count; ++index) {
                uint32_t length;
                const uint8_t *equals;

                if (offset > payload_len || payload_len - offset < 4) {
                    goto fail;
                }
                length = read_u32(payload + offset);
                offset += 4;
                if (length == 0 || length > MAX_ARGUMENT_LEN ||
                    length > payload_len - offset ||
                    memchr(payload + offset, '\0', length) != NULL) {
                    goto fail;
                }
                equals = memchr(payload + offset, '=', length);
                if (equals == NULL || equals == payload + offset) {
                    goto fail;
                }
                for (uint16_t previous = 0; previous < index; ++previous) {
                    size_t name_length = (size_t)(equals - (payload + offset));
                    const char *prior = config->environment[previous];
                    if (strcspn(prior, "=") == name_length &&
                        memcmp(prior, payload + offset, name_length) == 0) {
                        goto fail;
                    }
                }
                config->environment[index] = malloc((size_t)length + 1);
                if (config->environment[index] == NULL) {
                    goto fail;
                }
                memcpy(config->environment[index], payload + offset, length);
                config->environment[index][length] = '\0';
                offset += length;
            }
        }
        if (offset != payload_len) {
            goto fail;
        }
    }
    *workload_argv = arguments;
    return 0;

fail:
    for (index = 0; index < argc; ++index) {
        free(arguments[index]);
    }
    free(arguments);
    free(config->cwd);
    config->cwd = NULL;
    if (config->environment != NULL) {
        for (index = 0; index < config->environment_count; ++index) {
            free(config->environment[index]);
        }
        free(config->environment);
        config->environment = NULL;
    }
    return -1;
}

static void free_arguments(char **arguments)
{
    size_t index;

    if (arguments == NULL) {
        return;
    }
    for (index = 0; arguments[index] != NULL; ++index) {
        free(arguments[index]);
    }
    free(arguments);
}

static void free_exec_config(struct exec_config *config)
{
    uint16_t index;

    free(config->cwd);
    for (index = 0; index < config->environment_count; ++index) {
        free(config->environment[index]);
    }
    free(config->environment);
    memset(config, 0, sizeof(*config));
}

/*
 * Writes the launch helper's configuration. When the caller has entered the
 * working directory already, the configuration says so instead of naming it.
 */
static int write_exec_config(
    int fd,
    const struct exec_config *config,
    int cwd_entered)
{
    uint8_t header[8];
    uint16_t flags = 0;
    const char *cwd = cwd_entered ? NULL : config->cwd;
    uint16_t index;

    if (cwd_entered) {
        flags |= EXEC_CWD_ENTERED;
    } else if (cwd != NULL) {
        flags |= EXEC_CWD_PRESENT;
    }
    if (config->environment_present) {
        flags |= EXEC_ENVIRONMENT_PRESENT;
    }
    if (config->inherit_default_env) {
        flags |= EXEC_INHERIT_DEFAULT_ENV;
    }
    write_u16(header, flags);
    write_u16(header + 2, config->environment_count);
    write_u32(header + 4, cwd == NULL ? 0 : (uint32_t)strlen(cwd));
    if (write_all(fd, header, sizeof(header)) != 0 ||
        (cwd != NULL && write_all(fd, cwd, strlen(cwd)) != 0)) {
        return -1;
    }
    for (index = 0; index < config->environment_count; ++index) {
        uint32_t length = (uint32_t)strlen(config->environment[index]);
        uint8_t encoded_length[4];

        write_u32(encoded_length, length);
        if (write_all(fd, encoded_length, sizeof(encoded_length)) != 0 ||
            write_all(fd, config->environment[index], length) != 0) {
            return -1;
        }
    }
    return 0;
}

static int create_exec_config_fd(const struct exec_config *config, int cwd_entered)
{
    int fd = memfd_create("nvx-exec-config", MFD_CLOEXEC | MFD_ALLOW_SEALING);

    if (fd < 0) {
        return -1;
    }
    /* A sealed, bounded anonymous file avoids depending on pipe capacity. */
    if (write_exec_config(fd, config, cwd_entered) != 0 ||
        lseek(fd, 0, SEEK_SET) < 0 ||
        fcntl(fd, F_ADD_SEALS,
              F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int launch_workload(int argc, char **argv)
{
    char *end = NULL;
    long descriptor;
    uint8_t header[8];
    uint16_t flags;
    uint16_t environment_count;
    uint32_t cwd_len;
    char *cwd = NULL;
    char **environment = NULL;
    uint16_t index;

    if (argc < 5 || strcmp(argv[1], "--exec-config-fd") != 0 ||
        strcmp(argv[3], "--") != 0 || argv[4][0] != '/') {
        return 125;
    }
    errno = 0;
    descriptor = strtol(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0' ||
        descriptor < 0 || descriptor > INT32_MAX ||
        read_exact((int)descriptor, header, sizeof(header)) != 0) {
        return 125;
    }
    flags = read_u16(header);
    environment_count = read_u16(header + 2);
    cwd_len = read_u32(header + 4);
    if ((flags &
         ~(EXEC_CWD_PRESENT | EXEC_ENVIRONMENT_PRESENT |
           EXEC_INHERIT_DEFAULT_ENV | EXEC_CWD_ENTERED)) != 0 ||
        ((flags & EXEC_CWD_ENTERED) != 0 && (flags & EXEC_CWD_PRESENT) != 0) ||
        environment_count > MAX_ENVIRONMENT ||
        ((flags & EXEC_CWD_PRESENT) == 0 && cwd_len != 0) ||
        ((flags & EXEC_CWD_PRESENT) != 0 &&
         (cwd_len == 0 || cwd_len > MAX_ARGUMENT_LEN)) ||
        ((flags & EXEC_ENVIRONMENT_PRESENT) == 0 &&
         (environment_count != 0 ||
          (flags & EXEC_INHERIT_DEFAULT_ENV) != 0))) {
        return 125;
    }
    if (cwd_len != 0) {
        cwd = malloc((size_t)cwd_len + 1);
        if (cwd == NULL || read_exact((int)descriptor, cwd, cwd_len) != 0) {
            free(cwd);
            return 125;
        }
        cwd[cwd_len] = '\0';
    }
    environment = calloc(
        (size_t)environment_count + 1, sizeof(*environment));
    if (environment == NULL) {
        free(cwd);
        return 125;
    }
    for (index = 0; index < environment_count; ++index) {
        uint8_t encoded_length[4];
        uint32_t length;

        if (read_exact((int)descriptor, encoded_length, 4) != 0) {
            goto fail;
        }
        length = read_u32(encoded_length);
        if (length == 0 || length > MAX_ARGUMENT_LEN) {
            goto fail;
        }
        environment[index] = malloc((size_t)length + 1);
        if (environment[index] == NULL ||
            read_exact((int)descriptor, environment[index], length) != 0) {
            goto fail;
        }
        if (memchr(environment[index], '\0', length) != NULL ||
            environment[index][0] == '=' ||
            memchr(environment[index], '=', length) == NULL) {
            goto fail;
        }
        environment[index][length] = '\0';
    }
    close((int)descriptor);
    if (cwd != NULL &&
        (cwd[0] != '/' || memchr(cwd, '\0', cwd_len) != NULL)) {
        dprintf(STDERR_FILENO, "nvx-managed-agent: invalid working directory\n");
        goto fail;
    }
    if (unsetenv("NVX_EXEC_CONFIG_FD") != 0) {
        goto fail;
    }
    if ((flags & EXEC_CWD_ENTERED) == 0) {
        const char *directory = cwd == NULL ? "/" : cwd;

        if (chdir(directory) != 0) {
            dprintf(
                STDERR_FILENO,
                "nvx-managed-agent: cannot use working directory %s: %s\n",
                directory,
                strerror(errno));
            goto fail;
        }
        if (((flags & EXEC_ENVIRONMENT_PRESENT) == 0 ||
             (flags & EXEC_INHERIT_DEFAULT_ENV) != 0) &&
            export_working_directory(directory) != 0) {
            dprintf(
                STDERR_FILENO,
                "nvx-managed-agent: cannot configure working directory "
                "environment: %s\n",
                strerror(errno));
            goto fail;
        }
    }
    if ((flags & EXEC_ENVIRONMENT_PRESENT) != 0) {
        if ((flags & EXEC_INHERIT_DEFAULT_ENV) == 0 && clearenv() != 0) {
            goto fail;
        }
        for (index = 0; index < environment_count; ++index) {
            if (putenv(environment[index]) != 0) {
                goto fail;
            }
            environment[index] = NULL;
        }
    }
    execv(argv[4], &argv[4]);
    dprintf(
        STDERR_FILENO,
        "nvx-managed-agent: cannot execute workload: %s\n",
        strerror(errno));

fail:
    free(cwd);
    for (index = 0; index < environment_count; ++index) {
        free(environment[index]);
    }
    free(environment);
    return 125;
}

static int stream_output(
    struct control_session *session,
    uint64_t request_id,
    int fd,
    uint8_t kind,
    size_t *output_bytes)
{
    uint8_t buffer[OUTPUT_CHUNK_BYTES];
    ssize_t count;

    for (;;) {
        count = read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            if (*output_bytes > MAX_OUTPUT_BYTES - (size_t)count) {
                return -2;
            }
            *output_bytes += (size_t)count;
            if (send_app_frame(
                    session,
                    kind,
                    request_id,
                    0,
                    buffer,
                    (uint32_t)count) != 0) {
                return -1;
            }
        } else if (count == 0) {
            return 1;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        } else {
            /* The pipe, not the control channel: only this execution is affected. */
            return -3;
        }
    }
}

/* Discards output of a workload whose host is gone; returns 1 at end-of-file. */
static int drain_output(int fd)
{
    uint8_t buffer[OUTPUT_CHUNK_BYTES];
    ssize_t count;

    for (;;) {
        count = read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            continue;
        }
        if (count == 0) {
            return 1;
        }
        if (errno == EINTR) {
            continue;
        }
        /* Nothing consumes this stream any more, so a read error ends it like end-of-file. */
        return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : 1;
    }
}

/*
 * Waits until a direct-mode child either executes setpriv, which closes the
 * close-on-exec launch pipe, or reports why it cannot launch the workload.
 * Returns 0 once setpriv runs, 1 with `failure` filled in, or -1 on error.
 */
static int read_launch_failure(int fd, struct launch_failure *failure)
{
    uint8_t buffer[sizeof(*failure)];
    size_t length = 0;

    while (length < sizeof(buffer)) {
        ssize_t count = read(fd, buffer + length, sizeof(buffer) - length);

        if (count > 0) {
            length += (size_t)count;
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            return -1;
        }
    }
    if (length == 0) {
        return 0;
    }
    if (length != sizeof(buffer)) {
        errno = EPROTO;
        return -1;
    }
    memcpy(failure, buffer, sizeof(*failure));
    return 1;
}

/*
 * Refuses a workload whose working directory it cannot enter. Nothing of the
 * workload ran; a diagnostic on its standard error names the directory, and
 * the refusal carries the error number.
 */
static int refuse_working_directory(
    struct control_session *session,
    uint64_t request_id,
    const char *directory,
    int error)
{
    char message[MAX_GUEST_PATH + 128];
    int length = snprintf(
        message,
        sizeof(message),
        "nvx-managed-agent: cannot enter working directory %s: %s\n",
        directory,
        strerror(error));

    if (length > 0 && (size_t)length < sizeof(message) &&
        send_app_frame(
            session, APP_STDERR, request_id, 0, message, (uint32_t)length) != 0) {
        return -1;
    }
    return send_app_error(session, request_id, error, "cwd-failed");
}

static void close_pipe(int pipe_fds[2])
{
    unsigned int index;

    for (index = 0; index < 2; ++index) {
        if (pipe_fds[index] >= 0) {
            close(pipe_fds[index]);
            pipe_fds[index] = -1;
        }
    }
}

/*
 * Starts one execution: its cgroup leaf and limits, its output pipes and its
 * child. Nothing here waits for the workload; the scheduler drives the slot
 * forward, which is what lets several executions run at once.
 *
 * On failure the caller still owns `workload_argv` and `exec_config`, and this
 * function has already told the host why.
 */
static int start_slot(
    struct control_session *session,
    const struct agent_config *config,
    struct exec_slot *slot,
    uint64_t request_id,
    uint32_t timeout_ms,
    char **workload_argv,
    const struct exec_config *exec_config)
{
    const char *barrier = "/run/nvx/managed-container-start";
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    int exec_config_fd = -1;
    int launch_pipe[2] = {-1, -1};
    int launch_failed = 0;
    int wants_limits = exec_config->mem_mb != 0 || exec_config->cpu_percent != 0 ||
                       exec_config->pids_max != 0;
    pid_t child;

    memset(slot, 0, sizeof(*slot));
    slot->stdout_fd = -1;
    slot->stderr_fd = -1;
    slot->launch_fd = -1;
    slot->request_id = request_id;
    if (config->direct) {
        /*
         * The limits go on the leaf before the child joins it, so a workload
         * never runs without the limits the caller asked for.
         */
        /* Accounting and group OOM handling also apply to uncapped executions. */
        if (prepare_cgroup_root(1,
                exec_config->cpu_percent != 0) != 0 ||
            create_slot_cgroup(
                slot, exec_config->mem_mb, exec_config->cpu_percent, exec_config->pids_max) !=
                0) {
            portb_error("exec-cgroup", errno);
            remove_cgroup(slot->cgroup);
            slot->cgroup_ready = 0;
            return send_app_error(session, request_id, 125,
                wants_limits ? "limit-unsupported" : "containment-failed");
        }
    } else {
        unlink(barrier);
        if (mkfifo(barrier, 0600) != 0) {
            return send_app_error(session, request_id, 125, "launch-failed");
        }
    }
    if (pipe2(stdout_pipe, O_CLOEXEC) != 0 ||
        pipe2(stderr_pipe, O_CLOEXEC) != 0 ||
        (exec_config_fd = create_exec_config_fd(exec_config, config->direct)) < 0 ||
        (config->direct && pipe2(launch_pipe, O_CLOEXEC) != 0)) {
        unlink(barrier);
        close_pipe(stdout_pipe);
        close_pipe(stderr_pipe);
        if (exec_config_fd >= 0) {
            close(exec_config_fd);
        }
        remove_cgroup(slot->cgroup);
        slot->cgroup_ready = 0;
        return send_app_error(session, request_id, 125, "launch-failed");
    }

    /* The child reads this across fork(); the parent clears it right after. A
     * child joins a leaf only when this execution really has one. */
    g_child_cgroup = (config->direct && slot->cgroup_ready) ? slot->cgroup : NULL;
    child = fork();
    if (child < 0) {
        g_child_cgroup = NULL;
        close_pipe(stdout_pipe);
        close_pipe(stderr_pipe);
        close(exec_config_fd);
        close_pipe(launch_pipe);
        unlink(barrier);
        remove_cgroup(slot->cgroup);
        slot->cgroup_ready = 0;
        return send_app_error(session, request_id, 125, "launch-failed");
    }
    if (child == 0) {
        int null_fd;
        char config_fd[32];

        /* fork inherits the agent's OOM exemption. Restore eligibility while
         * still root, before setpriv drops capabilities or user code runs. */
        if (write_cgroup_file("/proc/self", "oom_score_adj", "0") != 0) {
            _exit(125);
        }
        setpgid(0, 0);
        if (fcntl(exec_config_fd, F_SETFD, 0) != 0 ||
            snprintf(
                config_fd, sizeof(config_fd), "%d", exec_config_fd) <= 0) {
            _exit(125);
        }
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        null_fd = open("/dev/null", O_RDONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            close(null_fd);
        }
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);
        if (config->direct) {
            const char *directory =
                exec_config->cwd == NULL ? "/" : exec_config->cwd;

            close(launch_pipe[0]);
            enter_workload_directory(config, directory, launch_pipe[1]);
            /*
             * A request that replaces the environment controls PWD itself;
             * one that layers entries over the default keeps this PWD unless
             * an entry names it.
             */
            if ((!exec_config->environment_present ||
                 exec_config->inherit_default_env) &&
                export_working_directory(directory) != 0) {
                report_launch_failure(launch_pipe[1], LAUNCH_STAGE_SETUP, errno);
            }
            exec_direct(config, config_fd, workload_argv);
        }
        exec_sandbox(config, barrier, config_fd, workload_argv);
    }

    g_child_cgroup = NULL;
    setpgid(child, child);
    close(exec_config_fd);
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    /*
     * Only the child writes to the launch pipe, and it closes its end when it
     * executes setpriv. Its report is read once it has exited, so the agent
     * keeps serving control traffic while the child enters the directory.
     */
    if (config->direct) {
        close(launch_pipe[1]);
        launch_pipe[1] = -1;
    }
    launch_failed = make_nonblocking(stdout_pipe[0]) != 0 ||
                    make_nonblocking(stderr_pipe[0]) != 0;
    if (!launch_failed && !config->direct) {
        int barrier_result;

        if (write_pid_to_cgroup(child) != 0) {
            launch_failed = 1;
        } else {
            barrier_result = release_container_barrier(barrier, child);
            launch_failed = barrier_result < 0;
        }
    }
    if (launch_failed) {
        kill(-child, SIGKILL);
        if (config->direct && slot->cgroup_ready) {
            (void)kill_cgroup(slot->cgroup);
        }
        waitpid(child, NULL, 0);
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        close_pipe(launch_pipe);
        unlink(barrier);
        remove_cgroup(slot->cgroup);
        slot->cgroup_ready = 0;
        return send_app_error(session, request_id, 125, "launch-failed");
    }
    unlink(barrier);
    slot->child = child;
    slot->workload_argv = workload_argv;
    slot->config = *exec_config;
    slot->timeout_ms = timeout_ms;
    slot->started_ms = monotonic_milliseconds();
    slot->output_bytes = 0;
    slot->stdout_fd = stdout_pipe[0];
    slot->stderr_fd = stderr_pipe[0];
    slot->launch_fd = launch_pipe[0];
    slot->flags = SLOT_USED | SLOT_STDOUT_OPEN | SLOT_STDERR_OPEN;
    return 0;
}

/* The slot of one execution, or NULL when the request is not running here. */
static struct exec_slot *slot_for_request(
    struct exec_slot *slots, size_t count, uint64_t request_id)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        if ((slots[index].flags & SLOT_USED) != 0 && slots[index].request_id == request_id) {
            return &slots[index];
        }
    }
    return NULL;
}

static struct exec_slot *free_slot(struct exec_slot *slots, size_t count)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        if ((slots[index].flags & SLOT_USED) == 0) {
            return &slots[index];
        }
    }
    return NULL;
}

/* Releases everything a slot owns. The caller has already reaped its child. */
static void release_slot(struct exec_slot *slot)
{
    if (slot->stdout_fd >= 0) {
        close(slot->stdout_fd);
    }
    if (slot->stderr_fd >= 0) {
        close(slot->stderr_fd);
    }
    if (slot->launch_fd >= 0) {
        close(slot->launch_fd);
    }
    free_arguments(slot->workload_argv);
    free_exec_config(&slot->config);
    if (slot->cgroup_ready) {
        remove_cgroup(slot->cgroup);
    }
    memset(slot, 0, sizeof(*slot));
    slot->stdout_fd = -1;
    slot->stderr_fd = -1;
    slot->launch_fd = -1;
}

/* Kills one execution and everything it started. */
static void terminate_slot(const struct agent_config *config, struct exec_slot *slot)
{
    if ((slot->flags & SLOT_USED) == 0) {
        return;
    }
    if (slot->child > 0 && (slot->flags & SLOT_EXITED) == 0) {
        (void)kill(-slot->child, SIGKILL);
        (void)kill(slot->child, SIGKILL);
    }
    if (config->direct && slot->cgroup_ready) {
        (void)kill_cgroup(slot->cgroup);
    }
}

/*
 * Reports the terminal state of an execution whose child has exited and whose
 * output pipes have reached end-of-file, then releases it. The execution's
 * cgroup is settled first, so nothing it left behind survives to be seen by a
 * later execution.
 */
static int finish_slot(
    struct control_session *session,
    const struct agent_config *config,
    struct exec_slot *slots,
    size_t count,
    struct exec_slot *slot)
{
    const int abandoned = (slot->flags & SLOT_ABANDONED) != 0;
    int result = 0;

    if (slot->launch_fd >= 0) {
        slot->launch_report = read_launch_failure(slot->launch_fd, &slot->launch_failure);
        if (slot->launch_report < 0) {
            portb_error("exec-launch-report", errno);
        }
        close(slot->launch_fd);
        slot->launch_fd = -1;
    }
    if (config->direct && slot->cgroup_ready) {
        int settled = settle_cgroup(
            slot->cgroup, slots, count, &slot->settle_attempts);

        if (settled > 0) {
            /* Still emptying: nothing is reported or released yet, and the loop comes back. */
            return 1;
        }
        if (settled < 0) {
            portb_error("exec-cgroup-settle", errno);
            if (!abandoned) {
                result = send_app_error(session, slot->request_id, 125, "containment-failed");
            }
            /* The leaf keeps whatever could not be killed; it stays for the
             * next examination instead of being reported as cleaned. */
            slot->cgroup_ready = 0;
            release_slot(slot);
            return result;
        }
    }
    if (!abandoned) {
        const char *oom_category = slot_oom_category(slot);

        if (slot->launch_report > 0 && slot->launch_failure.stage == LAUNCH_STAGE_CWD) {
            result = refuse_working_directory(session, slot->request_id,
                slot->config.cwd == NULL ? "/" : slot->config.cwd,
                slot->launch_failure.error);
        } else if (slot->launch_report > 0) {
            portb_error("exec-launch", slot->launch_failure.error);
            result = send_app_error(session, slot->request_id, 125, "launch-failed");
        } else if ((slot->flags & SLOT_CANCELLED) != 0) {
            result = send_app_frame(
                session, APP_EXIT, slot->request_id, 128 + SIGKILL, "cancelled", 9);
        } else if ((slot->flags & SLOT_TIMED_OUT) != 0) {
            result = send_app_frame(
                session, APP_EXIT, slot->request_id, 124, "timeout", 7);
        } else if ((slot->flags & SLOT_OUTPUT_LIMITED) != 0) {
            result = send_app_frame(
                session, APP_EXIT, slot->request_id, 125, "output-limit", 12);
        } else if (oom_category != NULL) {
            result = send_app_frame(session, APP_EXIT, slot->request_id,
                128 + SIGKILL, oom_category, strlen(oom_category));
        } else if (WIFEXITED(slot->wait_status)) {
            result = send_app_frame(session, APP_EXIT, slot->request_id,
                WEXITSTATUS(slot->wait_status), "exit", 4);
        } else if (WIFSIGNALED(slot->wait_status)) {
            result = send_app_frame(session, APP_EXIT, slot->request_id,
                128 + WTERMSIG(slot->wait_status), "signal", 6);
        } else {
            result = send_app_frame(
                session, APP_EXIT, slot->request_id, 125, "failed", 6);
        }
    }
    release_slot(slot);
    return result;
}

/*
 * Kills every execution and waits (bounded) until their cgroups are empty.
 * Used when the agent stops, and when the host that could observe the
 * executions is gone: in the latter case the slots are marked abandoned first,
 * so no reply is sent for them in the old epoch.
 */
static int terminate_all_slots(
    const struct agent_config *config, struct exec_slot *slots, size_t count)
{
    size_t index;
    int result = 0;

    for (index = 0; index < count; ++index) {
        if ((slots[index].flags & SLOT_USED) != 0) {
            terminate_slot(config, &slots[index]);
        }
    }
    for (index = 0; index < count; ++index) {
        struct exec_slot *slot = &slots[index];

        if ((slot->flags & SLOT_USED) == 0) {
            continue;
        }
        if (config->direct && slot->cgroup_ready) {
            int settled;

            /* Shutting down, so this pass may keep waiting; the bound is per attempt. */
            do {
                settled = settle_cgroup(
                    slot->cgroup, slots, count, &slot->settle_attempts);
            } while (settled > 0);
            if (settled < 0) {
                portb_error("exec-cgroup-settle", errno);
                result = -1;
                continue;
            }
        }
        if ((slot->flags & SLOT_EXITED) == 0 && slot->child > 0) {
            (void)waitpid(slot->child, NULL, 0);
        }
        release_slot(slot);
    }
    return result;
}

/*
 * Direct mode alone sets up host mappings, gives each workload a cgroup, and
 * refuses a working directory that the workload cannot enter as cwd-failed.
 */
static uint32_t agent_features(const struct agent_config *config)
{
    uint32_t features =
        FEATURE_CANCEL | FEATURE_WORKLOAD_ACCOUNT | FEATURE_EXEC_ENVIRONMENT;

    if (config->direct) {
        features |= FEATURE_HOST_MAPPING_TABLE | FEATURE_RUNTIME_MAPPINGS | FEATURE_EXEC_CGROUP |
                    FEATURE_EXEC_CWD | FEATURE_EXEC_SLOTS | FEATURE_EXEC_LIMITS;
    }
    return features;
}

/*
 * Mounts one mapping that APP_MAPS appends at run time and lists its target for
 * APP_UNMAP. A failure leaves the agent as it was: unlike a mapping of the
 * announced table, it does not make later workloads fail, and the sequence
 * number is not used up, so the host may retry. A full list is reported as
 * "mapping-limit" so that the host can tell it from a failed mount.
 */
static int mount_runtime_mapping(
    struct control_session *session,
    struct host_mappings *mappings,
    uint64_t request_id,
    const char *source,
    const char *target,
    int read_only)
{
    uint32_t slot;
    uint32_t free_slot = MAX_RUNTIME_MAPPINGS;
    char *copy;

    for (slot = 0; slot < MAX_RUNTIME_MAPPINGS; ++slot) {
        if (mappings->runtime_targets[slot] == NULL) {
            if (free_slot == MAX_RUNTIME_MAPPINGS) {
                free_slot = slot;
            }
        } else if (strcmp(mappings->runtime_targets[slot], target) == 0) {
            return send_app_error(session, request_id, EEXIST, "mapping-failed");
        }
    }
    if (free_slot == MAX_RUNTIME_MAPPINGS || mappings->runtime_next == UINT32_MAX) {
        return send_app_error(session, request_id, ENOSPC, "mapping-limit");
    }
    copy = strdup(target);
    if (copy == NULL) {
        return send_app_error(session, request_id, ENOMEM, "mapping-failed");
    }
    if (apply_host_mapping(source, target, read_only) != 0) {
        int status = errno;

        free(copy);
        portb_error("host-mapping", status);
        return send_app_error(session, request_id, status, "mapping-failed");
    }
    mappings->runtime_targets[free_slot] = copy;
    ++mappings->runtime_next;
    return send_app_frame(session, APP_READY, request_id, 0, NULL, 0);
}

/*
 * Unmounts the runtime mapping at the guest path that an APP_UNMAP request
 * carries. Only a mapping that APP_MAPS appended at run time qualifies, never
 * one of the announced table. The session is serial, so no workload uses the
 * mapping, and the host removes the export only after this succeeds.
 */
static int handle_unmap(
    struct control_session *session,
    struct host_mappings *mappings,
    const struct app_request *request)
{
    char target[MAX_GUEST_PATH];
    uint32_t slot;

    if (mappings->failed || mappings->expected == 0 || request->payload_len == 0 ||
        request->payload_len >= sizeof(target) || request->payload[0] != '/' ||
        memchr(request->payload, '\0', request->payload_len) != NULL) {
        return send_app_error(session, request->request_id, 22, "invalid-request");
    }
    memcpy(target, request->payload, request->payload_len);
    target[request->payload_len] = '\0';
    for (slot = 0; slot < MAX_RUNTIME_MAPPINGS; ++slot) {
        if (mappings->runtime_targets[slot] != NULL &&
            strcmp(mappings->runtime_targets[slot], target) == 0) {
            if (umount(target) != 0) {
                int status = errno;

                portb_error("host-unmap", status);
                return send_app_error(session, request->request_id, status, "mapping-failed");
            }
            free(mappings->runtime_targets[slot]);
            mappings->runtime_targets[slot] = NULL;
            return send_app_frame(session, APP_READY, request->request_id, 0, NULL, 0);
        }
    }
    return send_app_error(session, request->request_id, 22, "invalid-request");
}

/*
 * Mounts the entries FIRST to FIRST + COUNT - 1 of the host mapping table that
 * an APP_MAPS request carries after its 32-bit FIRST and COUNT. Entries of the
 * announced table arrive in order and only up to the number that nvx_maps=
 * announced, before any workload runs. The whole request is checked before
 * anything is mounted, and a mapping that fails to mount fails every later
 * workload.
 *
 * Once the announced table is mounted, a request instead appends one runtime
 * mapping: FIRST is then the sequence number of runtime requests (not a table
 * index), and COUNT is 1. Without an announced table (a layered root never
 * parses nvx_maps=) there is nothing to append to, and the request is invalid.
 */
static int handle_host_mappings(
    struct control_session *session,
    struct host_mappings *mappings,
    const struct app_request *request)
{
    char source[MAX_GUEST_PATH];
    char target[MAX_GUEST_PATH];
    uint32_t first;
    uint32_t count;
    uint32_t index;
    uint32_t offset = MAPS_HEADER_LEN;
    int read_only;
    int runtime;

    if (mappings->failed || request->payload_len < MAPS_HEADER_LEN) {
        return send_app_error(session, request->request_id, 22, "invalid-request");
    }
    first = read_u32(request->payload);
    count = read_u32(request->payload + 4);
    runtime = mappings->expected != 0 && mappings->applied >= mappings->expected;
    if (count == 0 || first != (runtime ? mappings->runtime_next : mappings->applied) ||
        (runtime ? count != 1 : count > mappings->expected - mappings->applied)) {
        return send_app_error(session, request->request_id, 22, "invalid-request");
    }
    for (index = 0; index < count; ++index) {
        if (decode_host_mapping(
                request->payload, request->payload_len, &offset, source, target,
                &read_only) != 0) {
            return send_app_error(session, request->request_id, 22, "invalid-request");
        }
    }
    if (offset != request->payload_len) {
        return send_app_error(session, request->request_id, 22, "invalid-request");
    }
    if (runtime) {
        /* The one entry that was just decoded. */
        return mount_runtime_mapping(
            session, mappings, request->request_id, source, target, read_only);
    }
    offset = MAPS_HEADER_LEN;
    for (index = 0; index < count; ++index) {
        decode_host_mapping(
            request->payload, request->payload_len, &offset, source, target, &read_only);
        if (apply_host_mapping(source, target, read_only) != 0) {
            int status = errno;

            mappings->failed = 1;
            portb_error("host-mapping", status);
            dprintf(
                STDERR_FILENO,
                "NVX-MANAGED-ERROR: stage=host-mapping status=%d entry=%u\n",
                status,
                (unsigned)(first + index));
            return send_app_error(session, request->request_id, status, "mapping-failed");
        }
        ++mappings->applied;
    }
    return send_app_frame(session, APP_READY, request->request_id, 0, NULL, 0);
}

/* Serves one application request of the authenticated host. */
static int handle_app_request(
    struct control_session *session,
    const struct agent_config *config,
    struct host_mappings *mappings,
    struct exec_slot *slots,
    size_t count,
    const struct app_request *request)
{
    char **workload_argv = NULL;
    uint8_t features[4];
    struct exec_config exec_config = {0};
    uint32_t timeout_ms = 0;
    int result;

    switch (request->kind) {
    case APP_PING:
        if (request->payload_len != 0) {
            portb_error("ping-payload", (int)request->payload_len);
            return send_app_error(
                session, request->request_id, 22, "invalid-request");
        }
        result = send_app_frame(
            session, APP_READY, request->request_id, 0, NULL, 0);
        if (result != 0) {
            portb_error("ping-ready", errno);
        }
        return result;
    case APP_EXEC: {
        struct exec_slot *slot = NULL;
        size_t capacity = config->direct ? count : 1U;
        size_t live = 0;
        size_t index;

        /* Workloads must not run without the host paths that they expect. */
        if (mappings->applied != mappings->expected) {
            return send_app_error(
                session, request->request_id, EAGAIN, "mappings-incomplete");
        }
        if (decode_exec_payload(
                request->payload,
                request->payload_len,
                &timeout_ms,
                &workload_argv,
                &exec_config) != 0) {
            return send_app_error(
                session, request->request_id, 22, "invalid-request");
        }
        for (index = 0; index < count; ++index) {
            live += (slots[index].flags & SLOT_USED) != 0;
        }
        if (live < capacity) {
            slot = free_slot(slots, count);
        }
        if (slot == NULL) {
            /*
             * The agent is at capacity. Nothing was registered, so the host can
             * retry once an execution finishes; "busy" says exactly that.
             */
            free_arguments(workload_argv);
            free_exec_config(&exec_config);
            return send_app_error(session, request->request_id, 16, "busy");
        }
        result = start_slot(session, config, slot, request->request_id, timeout_ms,
            workload_argv, &exec_config);
        if (result != 0) {
            /* start_slot told the host why; the caller still owns these. */
            free_arguments(workload_argv);
            free_exec_config(&exec_config);
        }
        return result;
    }
    case APP_CANCEL: {
        struct exec_slot *slot;

        if (request->payload_len != 0) {
            return send_app_error(
                session, request->request_id, 22, "invalid-request");
        }
        slot = slot_for_request(slots, count, request->request_id);
        if (slot != NULL && (slot->flags & SLOT_EXITED) == 0) {
            /* Only the execution named by the request is terminated; its
             * siblings and the executions of other sessions keep running. */
            slot->flags |= SLOT_CANCELLED;
            terminate_slot(config, slot);
        }
        /* A cancel for an execution that already finished needs no reply: its
         * terminal event has been sent and says what happened. */
        return 0;
    }
    case APP_FEATURES:
        if (request->payload_len != 0) {
            return send_app_error(
                session, request->request_id, 22, "invalid-request");
        }
        write_u32(features, agent_features(config));
        return send_app_frame(
            session,
            APP_READY,
            request->request_id,
            0,
            features,
            sizeof(features));
    case APP_MAPS:
        return handle_host_mappings(session, mappings, request);
    case APP_UNMAP:
        return handle_unmap(session, mappings, request);
    case APP_STOP:
        if (request->payload_len != 0) {
            return -1;
        }
        /* Every execution ends before the VM does, so nothing is left to
         * outlive the acknowledgement. */
        (void)terminate_all_slots(config, slots, count);
        if (send_app_frame(
                session, APP_STOPPED, request->request_id, 0, NULL, 0) != 0) {
            return -1;
        }
        tcdrain(session->fd);
        return AGENT_STOPPED;
    default:
        return send_app_error(
            session, request->request_id, 95, "unsupported-operation");
    }
}

static int handle_data_record(
    struct control_session *session,
    const struct agent_config *config,
    struct host_mappings *mappings,
    struct exec_slot *slots,
    size_t count,
    const struct outer_record *record)
{
    struct app_request request;

    if (record->sequence != session->host_sequence) {
        portb_error("data-sequence", (int)record->sequence);
        return -1;
    }
    if (record->epoch != session->epoch ||
        memcmp(record->instance_id, session->instance_id, 16) != 0) {
        portb_error("data-identity", (int)record->epoch);
        return -1;
    }
    if (parse_app_request(record->payload, record->payload_len, &request) != 0) {
        portb_error("data-application", (int)record->payload_len);
        return -1;
    }
    ++session->host_sequence;
    if (send_credit(session, record->payload_len) != 0) {
        portb_error("data-credit", (int)record->payload_len);
        return -1;
    }
    return handle_app_request(session, config, mappings, slots, count, &request);
}

/*
 * The agent's event loop. One poll serves the control channel and every running
 * execution at once, so an execution that takes a long time never keeps the
 * agent from accepting, cancelling or reporting another one.
 */
static int run_agent(
    struct control_session *session,
    const struct agent_config *config,
    struct host_mappings *mappings)
{
    struct exec_slot slots[MAX_EXEC_SLOTS];
    struct outer_record record;
    size_t index;

    memset(slots, 0, sizeof(slots));
    for (index = 0; index < MAX_EXEC_SLOTS; ++index) {
        slots[index].stdout_fd = -1;
        slots[index].stderr_fd = -1;
        slots[index].launch_fd = -1;
    }
    if (send_guest_attach(session->fd) != 0) {
        return -1;
    }
    for (;;) {
        struct pollfd descriptors[1 + 2 * MAX_EXEC_SLOTS];
        size_t owners[1 + 2 * MAX_EXEC_SLOTS];
        unsigned char kinds[1 + 2 * MAX_EXEC_SLOTS];
        size_t wanted = 1;
        int poll_result;
        int channel_failed = 0;

        descriptors[0].fd = session->fd;
        descriptors[0].events = POLLIN;
        descriptors[0].revents = 0;
        owners[0] = 0;
        kinds[0] = 0;
        for (index = 0; index < MAX_EXEC_SLOTS; ++index) {
            struct exec_slot *slot = &slots[index];

            if ((slot->flags & SLOT_USED) == 0) {
                continue;
            }
            if ((slot->flags & SLOT_STDOUT_OPEN) != 0) {
                descriptors[wanted].fd = slot->stdout_fd;
                descriptors[wanted].events = POLLIN | POLLHUP;
                descriptors[wanted].revents = 0;
                owners[wanted] = index;
                kinds[wanted] = 1;
                ++wanted;
            }
            if ((slot->flags & SLOT_STDERR_OPEN) != 0) {
                descriptors[wanted].fd = slot->stderr_fd;
                descriptors[wanted].events = POLLIN | POLLHUP;
                descriptors[wanted].revents = 0;
                owners[wanted] = index;
                kinds[wanted] = 2;
                ++wanted;
            }
        }
        poll_result = poll(descriptors, (nfds_t)wanted, 25);
        if (poll_result < 0 && errno != EINTR) {
            (void)terminate_all_slots(config, slots, MAX_EXEC_SLOTS);
            return -1;
        }
        if (descriptors[0].revents != 0) {
            int result;

            if (read_outer_record(session->fd, &record) != 0) {
                portb_error("outer-read", errno);
                (void)terminate_all_slots(config, slots, MAX_EXEC_SLOTS);
                return -1;
            }
            if (record.type == OUTER_RESET) {
                if (acknowledge_reset(session, &record) != 0) {
                    portb_error("reset-ack", errno);
                    free_outer_record(&record);
                    (void)terminate_all_slots(config, slots, MAX_EXEC_SLOTS);
                    return -1;
                }
                /*
                 * The host that could observe these executions is gone. They
                 * are killed, their output is drained, and nothing is sent for
                 * them again: a reply in the new epoch would be a violation.
                 */
                for (index = 0; index < MAX_EXEC_SLOTS; ++index) {
                    if ((slots[index].flags & SLOT_USED) != 0) {
                        slots[index].flags |= SLOT_ABANDONED;
                        terminate_slot(config, &slots[index]);
                    }
                }
            } else if (record.type == OUTER_DATA) {
                result = handle_data_record(
                    session, config, mappings, slots, MAX_EXEC_SLOTS, &record);
                if (result == AGENT_STOPPED) {
                    free_outer_record(&record);
                    return AGENT_STOPPED;
                }
                if (result != 0) {
                    portb_error("data", errno);
                    free_outer_record(&record);
                    (void)terminate_all_slots(config, slots, MAX_EXEC_SLOTS);
                    return -1;
                }
            } else {
                portb_error("outer-type", record.type);
                free_outer_record(&record);
                (void)terminate_all_slots(config, slots, MAX_EXEC_SLOTS);
                return -1;
            }
            free_outer_record(&record);
        }
        /* Relay whatever output is ready, one chunk per open stream. */
        for (index = 1; index < wanted; ++index) {
            struct exec_slot *slot = &slots[owners[index]];
            const int is_stdout = kinds[index] == 1;
            const uint32_t open_bit = is_stdout ? SLOT_STDOUT_OPEN : SLOT_STDERR_OPEN;
            int fd = is_stdout ? slot->stdout_fd : slot->stderr_fd;
            int chunk;

            if (descriptors[index].revents == 0 || (slot->flags & open_bit) == 0) {
                continue;
            }
            chunk = (slot->flags & SLOT_ABANDONED) != 0
                        ? drain_output(fd)
                        : stream_output(session, slot->request_id, fd,
                              is_stdout ? APP_STDOUT : APP_STDERR, &slot->output_bytes);
            if (chunk == 1) {
                close(fd);
                if (is_stdout) {
                    slot->stdout_fd = -1;
                } else {
                    slot->stderr_fd = -1;
                }
                slot->flags &= ~open_bit;
            } else if (chunk < 0) {
                if (chunk == -2) {
                    slot->flags |= SLOT_OUTPUT_LIMITED;
                } else if (chunk == -3) {
                    /* One execution's pipe failed: end that execution, not the agent. */
                    portb_error("exec-pipe-read", errno);
                } else {
                    /* The control channel itself failed. */
                    channel_failed = 1;
                }
                terminate_slot(config, slot);
            }
        }
        if (channel_failed) {
            (void)terminate_all_slots(config, slots, MAX_EXEC_SLOTS);
            return -1;
        }
        reap_children(slots, MAX_EXEC_SLOTS);
        for (index = 0; index < MAX_EXEC_SLOTS; ++index) {
            struct exec_slot *slot = &slots[index];

            if ((slot->flags & SLOT_USED) == 0) {
                continue;
            }
            /*
             * A process the execution left behind must not hold its output
             * open, or the terminal event would wait for something the caller
             * no longer needs.
             */
            if ((slot->flags & (SLOT_EXITED | SLOT_STRAGGLERS_KILLED)) == SLOT_EXITED &&
                (slot->flags & (SLOT_STDOUT_OPEN | SLOT_STDERR_OPEN)) != 0) {
                slot->flags |= SLOT_STRAGGLERS_KILLED;
                if (config->direct && slot->cgroup_ready) {
                    (void)kill_cgroup(slot->cgroup);
                }
            }
            if ((slot->flags & SLOT_EXITED) == 0 && slot->timeout_ms != 0 &&
                monotonic_milliseconds() - slot->started_ms >= slot->timeout_ms) {
                slot->flags |= SLOT_TIMED_OUT;
                terminate_slot(config, slot);
            }
            if ((slot->flags & (SLOT_EXITED | SLOT_STDOUT_OPEN | SLOT_STDERR_OPEN)) ==
                SLOT_EXITED) {
                int finished =
                    finish_slot(session, config, slots, MAX_EXEC_SLOTS, slot);

                /* 1 means the execution's cgroup is still emptying: it is retried on the next
                 * loop iteration, so control traffic keeps being served in the meantime. */
                if (finished < 0) {
                    (void)terminate_all_slots(config, slots, MAX_EXEC_SLOTS);
                    return -1;
                }
            }
        }
    }
}

/*
 * Direct mode runs as PID 1 and powers the VM off itself. In sandbox mode the
 * init agent supervises this process and unmounts the live share, overlay,
 * layers, and scratch before it powers the VM off.
 */
static int finish_agent(const struct agent_config *config, int status)
{
    char code[12];

    if (config->direct) {
        snprintf(code, sizeof(code), "%d", status);
        execl("/sbin/nvx-exit", "nvx-exit", code, (char *)NULL);
    }
    return status;
}

int main(int argc, char **argv)
{
    struct control_session session = {0};
    struct host_mappings mappings = {0};
    struct agent_config config;
    int result;

    if (argc >= 2 && strcmp(argv[1], "--exec-config-fd") == 0) {
        return launch_workload(argc, argv);
    }
    if (argc != 8) {
        return 125;
    }
    /*
     * Keep the OOM killer away from the control plane.
     *
     * Executions without a request or deployment cap may exhaust the guest. The kernel
     * then picks a victim by oom_score, roughly its share of resident memory.
     * Without this exemption the agent is just another candidate, and killing it
     * fails every session on the VM instead of the single execution that caused
     * the pressure. nvx-time exempts its daemon the same way.
     *
     * The forked child explicitly restores oom_score_adj before dropping privileges.
     */
    if (write_cgroup_file("/proc/self", "oom_score_adj", "-1000") != 0) {
        /* Not fatal: the agent still serves, it is just not protected. */
        dprintf(
            STDERR_FILENO,
            "NVX-MANAGED-WARN: stage=oom-exemption status=%d\n",
            errno);
    }
    config.rootfs = argv[2];
    config.hostname = argv[3];
    config.uid = argv[4];
    config.gid = argv[5];
    config.user = argv[6];
    config.home = argv[7];
    config.direct = strcmp(config.rootfs, "-") == 0;
    session.fd = open_control_tty(argv[1]);
    if (session.fd < 0) {
        int status = errno;
        portb_error("control-open", status);
        dprintf(
            STDERR_FILENO,
            "NVX-MANAGED-ERROR: stage=control-open status=%d\n",
            status);
        return finish_agent(&config, 125);
    }
    if (config.direct && prepare_host_mappings(&mappings) != 0) {
        int status = errno;
        portb_error("host-mappings", status);
        dprintf(
            STDERR_FILENO,
            "NVX-MANAGED-ERROR: stage=host-mappings status=%d\n",
            status);
        close(session.fd);
        return finish_agent(&config, 125);
    }
    if (configure_control_tty(session.fd) != 0) {
        int status = errno;
        portb_error("control-tty", status);
        dprintf(
            STDERR_FILENO,
            "NVX-MANAGED-ERROR: stage=control-tty status=%d\n",
            status);
        close(session.fd);
        return finish_agent(&config, 125);
    }
    result = run_agent(&session, &config, &mappings);
    if (result == AGENT_STOPPED) {
        close(session.fd);
        return finish_agent(&config, 0);
    }
    if (result != 0) {
        int status = errno;
        portb_error("control-session", status);
        dprintf(
            STDERR_FILENO,
            "NVX-MANAGED-ERROR: stage=control-session status=%d\n",
            status);
        if (session.fd >= 0) {
            close(session.fd);
        }
        return finish_agent(&config, 125);
    }
    return 0;
}
