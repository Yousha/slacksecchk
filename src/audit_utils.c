#define _POSIX_C_SOURCE 200809L
#include "audit_utils.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <stdarg.h>

static int audit_color_mode = AUDIT_COLOR_AUTO;

void audit_set_color_mode(int mode) {
    if (mode >= AUDIT_COLOR_AUTO && mode <= AUDIT_COLOR_NEVER)
        audit_color_mode = mode;
}

int audit_color_enabled(void) {
    if (audit_color_mode == AUDIT_COLOR_ALWAYS)
        return 1;
    if (audit_color_mode == AUDIT_COLOR_NEVER || getenv("NO_COLOR") != NULL)
        return 0;
    const char *term = getenv("TERM");
    return isatty(STDOUT_FILENO) && (term == NULL || strcmp(term, "dumb") != 0);
}

static int audit_json_output = 0;
static audit_summary_t audit_summary = {0, 0, 0};
static audit_finding_t audit_findings[AUDIT_FINDING_MAX];
static size_t audit_findings_count = 0;
static char audit_current_rule[AUDIT_RULE_ID_SIZE] = "SSC-GENERAL-0000";
static char audit_current_category[AUDIT_CATEGORY_SIZE] = "general";

static void audit_copy_field(char *target, size_t target_size, const char *source) {
    if (target_size == 0)
        return;
    if (source == NULL)
        source = "";
    (void)snprintf(target, target_size, "%s", source);
}

static int audit_status_valid(const char *status) {
    return status != NULL &&
        (strcmp(status, AUDIT_STATUS_PASS) == 0 ||
         strcmp(status, AUDIT_STATUS_FAIL) == 0 ||
         strcmp(status, AUDIT_STATUS_WARN) == 0 ||
         strcmp(status, AUDIT_STATUS_INFO) == 0 ||
         strcmp(status, AUDIT_STATUS_NOT_APPLICABLE) == 0 ||
         strcmp(status, AUDIT_STATUS_ERROR) == 0);
}

static int audit_severity_valid(const char *severity) {
    return severity != NULL &&
        (strcmp(severity, AUDIT_SEVERITY_INFO) == 0 ||
         strcmp(severity, AUDIT_SEVERITY_LOW) == 0 ||
         strcmp(severity, AUDIT_SEVERITY_MEDIUM) == 0 ||
         strcmp(severity, AUDIT_SEVERITY_HIGH) == 0 ||
         strcmp(severity, AUDIT_SEVERITY_CRITICAL) == 0);
}

static int audit_field_terminated(const char *field, size_t size) {
    return field != NULL && memchr(field, '\0', size) != NULL;
}

static void audit_update_summary(const char *status) {
    if (strcmp(status, AUDIT_STATUS_PASS) == 0)
        audit_summary.passed++;
    else if (strcmp(status, AUDIT_STATUS_FAIL) == 0)
        audit_summary.failed++;
    else if (strcmp(status, AUDIT_STATUS_WARN) == 0 ||
             strcmp(status, AUDIT_STATUS_ERROR) == 0)
        audit_summary.unverified++;
}

void audit_reset_summary(void) {
    memset(&audit_summary, 0, sizeof(audit_summary));
    memset(audit_findings, 0, sizeof(audit_findings));
    audit_findings_count = 0;
    audit_copy_field(audit_current_rule, sizeof(audit_current_rule), "SSC-GENERAL-0000");
    audit_copy_field(audit_current_category, sizeof(audit_current_category), "general");
}

void audit_set_json_output(int enabled) {
    audit_json_output = enabled != 0;
}

void audit_set_current_rule(const char *rule_id, const char *category) {
    if (rule_id != NULL && rule_id[0] != '\0')
        audit_copy_field(audit_current_rule, sizeof(audit_current_rule), rule_id);
    if (category != NULL && category[0] != '\0')
        audit_copy_field(audit_current_category, sizeof(audit_current_category), category);
}

int audit_finding_add(const audit_finding_t *finding) {
    if (finding == NULL ||
        !audit_field_terminated(finding->rule_id, sizeof(finding->rule_id)) ||
        !audit_field_terminated(finding->title, sizeof(finding->title)) ||
        !audit_field_terminated(finding->description, sizeof(finding->description)) ||
        !audit_field_terminated(finding->severity, sizeof(finding->severity)) ||
        !audit_field_terminated(finding->category, sizeof(finding->category)) ||
        !audit_field_terminated(finding->status, sizeof(finding->status)) ||
        !audit_field_terminated(finding->evidence, sizeof(finding->evidence)) ||
        !audit_field_terminated(finding->remediation, sizeof(finding->remediation)) ||
        !audit_field_terminated(finding->references, sizeof(finding->references)) ||
        finding->rule_id[0] == '\0' || finding->title[0] == '\0' ||
        !audit_status_valid(finding->status) ||
        !audit_severity_valid(finding->severity) ||
        finding->category[0] == '\0' ||
        audit_findings_count >= AUDIT_FINDING_MAX)
        return -1;

    audit_finding_t *stored = &audit_findings[audit_findings_count];
    memset(stored, 0, sizeof(*stored));
    audit_copy_field(stored->rule_id, sizeof(stored->rule_id), finding->rule_id);
    audit_copy_field(stored->title, sizeof(stored->title), finding->title);
    audit_copy_field(stored->description, sizeof(stored->description), finding->description);
    audit_copy_field(stored->severity, sizeof(stored->severity), finding->severity);
    audit_copy_field(stored->category, sizeof(stored->category), finding->category);
    audit_copy_field(stored->status, sizeof(stored->status), finding->status);
    audit_copy_field(stored->evidence, sizeof(stored->evidence), finding->evidence);
    audit_copy_field(stored->remediation, sizeof(stored->remediation), finding->remediation);
    audit_copy_field(stored->references, sizeof(stored->references), finding->references);
    audit_findings_count++;
    audit_update_summary(stored->status);
    return 0;
}

size_t audit_finding_count(void) {
    return audit_findings_count;
}

const audit_finding_t *audit_finding_get(size_t index) {
    return index < audit_findings_count ? &audit_findings[index] : NULL;
}

void audit_get_summary(audit_summary_t *summary) {
    if (summary != NULL)
        *summary = audit_summary;
}

int audit_summary_exit_code(void) {
    if (audit_summary.failed != 0)
        return 1;
    if (audit_summary.unverified != 0)
        return 2;
    return 0;
}

static int audit_json_write_string(FILE *stream, const char *value) {
    if (stream == NULL || value == NULL || fputc('"', stream) == EOF)
        return -1;

    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
        switch (*p) {
            case '"': if (fputs("\\\"", stream) == EOF) return -1; break;
            case '\\': if (fputs("\\\\", stream) == EOF) return -1; break;
            case '\b': if (fputs("\\b", stream) == EOF) return -1; break;
            case '\f': if (fputs("\\f", stream) == EOF) return -1; break;
            case '\n': if (fputs("\\n", stream) == EOF) return -1; break;
            case '\r': if (fputs("\\r", stream) == EOF) return -1; break;
            case '\t': if (fputs("\\t", stream) == EOF) return -1; break;
            default:
                if (*p < 0x20) {
                    if (fprintf(stream, "\\u%04x", (unsigned int)*p) < 0)
                        return -1;
                } else if (fputc(*p, stream) == EOF) {
                    return -1;
                }
        }
    }
    return fputc('"', stream) == EOF ? -1 : 0;
}

static int audit_json_write_finding(FILE *stream, const audit_finding_t *finding) {
    if (fputs("{\"rule_id\":", stream) == EOF ||
        audit_json_write_string(stream, finding->rule_id) != 0 ||
        fputs(",\"title\":", stream) == EOF ||
        audit_json_write_string(stream, finding->title) != 0 ||
        fputs(",\"description\":", stream) == EOF ||
        audit_json_write_string(stream, finding->description) != 0 ||
        fputs(",\"severity\":", stream) == EOF ||
        audit_json_write_string(stream, finding->severity) != 0 ||
        fputs(",\"category\":", stream) == EOF ||
        audit_json_write_string(stream, finding->category) != 0 ||
        fputs(",\"status\":", stream) == EOF ||
        audit_json_write_string(stream, finding->status) != 0 ||
        fputs(",\"evidence\":", stream) == EOF ||
        audit_json_write_string(stream, finding->evidence) != 0 ||
        fputs(",\"remediation\":", stream) == EOF ||
        audit_json_write_string(stream, finding->remediation) != 0 ||
        fputs(",\"references\":", stream) == EOF ||
        audit_json_write_string(stream, finding->references) != 0 ||
        fputc('}', stream) == EOF)
        return -1;
    return 0;
}

int audit_write_json_summary(FILE *stream, const char *version) {
    if (stream == NULL || version == NULL)
        return -1;

    const char *status = audit_summary.failed != 0 ? "failed" :
                         audit_summary.unverified != 0 ? "unverified" : "passed";
    if (fputs("{\"schema_version\":2,\"tool\":\"slacksecchk\",\"version\":", stream) == EOF ||
        audit_json_write_string(stream, version) != 0)
        return -1;
    if (fprintf(stream,
                ",\"status\":\"%s\",\"summary\":{\"passed\":%lu,\"failed\":%lu,\"unverified\":%lu},\"findings\":[",
                status, audit_summary.passed, audit_summary.failed,
                audit_summary.unverified) < 0)
        return -1;

    for (size_t i = 0; i < audit_findings_count; i++) {
        if ((i != 0 && fputc(',', stream) == EOF) ||
            audit_json_write_finding(stream, &audit_findings[i]) != 0)
            return -1;
    }
    return fputs("]}\n", stream) == EOF ? -1 : 0;
}

static const char *audit_sarif_level(const char *severity) {
    if (strcmp(severity, AUDIT_SEVERITY_CRITICAL) == 0 ||
        strcmp(severity, AUDIT_SEVERITY_HIGH) == 0)
        return "error";
    if (strcmp(severity, AUDIT_SEVERITY_MEDIUM) == 0 ||
        strcmp(severity, AUDIT_SEVERITY_LOW) == 0)
        return "warning";
    return "note";
}

static int audit_sarif_status_reportable(const char *status) {
    return strcmp(status, AUDIT_STATUS_FAIL) == 0 ||
           strcmp(status, AUDIT_STATUS_WARN) == 0 ||
           strcmp(status, AUDIT_STATUS_ERROR) == 0 ||
           strcmp(status, AUDIT_STATUS_INFO) == 0;
}

static int audit_sarif_rule_seen(size_t before, const char *rule_id) {
    for (size_t i = 0; i < before; i++) {
        if (strcmp(audit_findings[i].rule_id, rule_id) == 0)
            return 1;
    }
    return 0;
}

static int audit_sarif_write_rule(FILE *stream, const audit_finding_t *finding) {
    if (fputs("{\"id\":", stream) == EOF ||
        audit_json_write_string(stream, finding->rule_id) != 0 ||
        fputs(",\"name\":", stream) == EOF ||
        audit_json_write_string(stream, finding->title) != 0 ||
        fputs(",\"shortDescription\":{\"text\":", stream) == EOF ||
        audit_json_write_string(stream, finding->description) != 0 ||
        fputs("},\"properties\":{\"category\":", stream) == EOF ||
        audit_json_write_string(stream, finding->category) != 0 ||
        fputs(",\"defaultSeverity\":", stream) == EOF ||
        audit_json_write_string(stream, finding->severity) != 0 ||
        fputs("}}", stream) == EOF)
        return -1;
    return 0;
}

static int audit_sarif_write_result(FILE *stream, const audit_finding_t *finding) {
    const char *message = finding->description[0] != '\0' ?
                          finding->description : finding->title;
    if (fputs("{\"ruleId\":", stream) == EOF ||
        audit_json_write_string(stream, finding->rule_id) != 0 ||
        fputs(",\"level\":", stream) == EOF ||
        audit_json_write_string(stream, audit_sarif_level(finding->severity)) != 0 ||
        fputs(",\"message\":{\"text\":", stream) == EOF ||
        audit_json_write_string(stream, message) != 0 ||
        fputs("},\"properties\":{\"status\":", stream) == EOF ||
        audit_json_write_string(stream, finding->status) != 0 ||
        fputs(",\"severity\":", stream) == EOF ||
        audit_json_write_string(stream, finding->severity) != 0 ||
        fputs(",\"category\":", stream) == EOF ||
        audit_json_write_string(stream, finding->category) != 0 ||
        fputs(",\"evidence\":", stream) == EOF ||
        audit_json_write_string(stream, finding->evidence) != 0 ||
        fputs(",\"remediation\":", stream) == EOF ||
        audit_json_write_string(stream, finding->remediation) != 0 ||
        fputs(",\"references\":", stream) == EOF ||
        audit_json_write_string(stream, finding->references) != 0 ||
        fputs("}}", stream) == EOF)
        return -1;
    return 0;
}

int audit_write_sarif_report(FILE *stream, const char *version) {
    if (stream == NULL || version == NULL)
        return -1;

    if (fputs("{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\","
              "\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{"
              "\"name\":\"SlackSecChk\",\"version\":", stream) == EOF ||
        audit_json_write_string(stream, version) != 0 ||
        fputs(",\"informationUri\":\"https://github.com/Yousha/slacksecchk\","
              "\"rules\":[", stream) == EOF)
        return -1;

    int first = 1;
    for (size_t i = 0; i < audit_findings_count; i++) {
        if (audit_sarif_rule_seen(i, audit_findings[i].rule_id))
            continue;
        if ((!first && fputc(',', stream) == EOF) ||
            audit_sarif_write_rule(stream, &audit_findings[i]) != 0)
            return -1;
        first = 0;
    }

    if (fputs("]}},\"results\":[", stream) == EOF)
        return -1;
    first = 1;
    for (size_t i = 0; i < audit_findings_count; i++) {
        if (!audit_sarif_status_reportable(audit_findings[i].status))
            continue;
        if ((!first && fputc(',', stream) == EOF) ||
            audit_sarif_write_result(stream, &audit_findings[i]) != 0)
            return -1;
        first = 0;
    }

    if (fprintf(stream,
                "],\"properties\":{\"summary\":{\"passed\":%lu,\"failed\":%lu,"
                "\"unverified\":%lu}}}]}\n",
                audit_summary.passed, audit_summary.failed,
                audit_summary.unverified) < 0)
        return -1;
    return 0;
}

/* Compatibility adapter: existing rule output is converted into structured findings. */
static void audit_record_legacy_output(const char *message) {
    if (message == NULL)
        return;

    const char *marker = NULL;
    const char *status = NULL;
    const char *severity = AUDIT_SEVERITY_INFO;
    if ((marker = strstr(message, "PASSED!")) != NULL) {
        status = AUDIT_STATUS_PASS;
    } else if ((marker = strstr(message, "FAILED!")) != NULL) {
        status = AUDIT_STATUS_FAIL;
        severity = AUDIT_SEVERITY_HIGH;
    } else if ((marker = strstr(message, "Notice:")) != NULL) {
        status = AUDIT_STATUS_WARN;
        severity = AUDIT_SEVERITY_MEDIUM;
    } else if ((marker = strstr(message, "Error:")) != NULL) {
        status = AUDIT_STATUS_ERROR;
        severity = AUDIT_SEVERITY_MEDIUM;
    }
    if (status == NULL)
        return;

    while (*marker != '\0' && !isspace((unsigned char)*marker))
        marker++;
    while (*marker == ' ' || *marker == '\t')
        marker++;

    char title[AUDIT_TITLE_SIZE];
    size_t title_length = strcspn(marker, "\r\n");
    if (title_length >= sizeof(title))
        title_length = sizeof(title) - 1;
    memcpy(title, marker, title_length);
    title[title_length] = '\0';
    if (title[0] == '\0')
        audit_copy_field(title, sizeof(title), "Audit result");

    audit_finding_t finding;
    memset(&finding, 0, sizeof(finding));
    audit_copy_field(finding.rule_id, sizeof(finding.rule_id), audit_current_rule);
    audit_copy_field(finding.title, sizeof(finding.title), title);
    audit_copy_field(finding.description, sizeof(finding.description), title);
    audit_copy_field(finding.severity, sizeof(finding.severity), severity);
    audit_copy_field(finding.category, sizeof(finding.category), audit_current_category);
    audit_copy_field(finding.status, sizeof(finding.status), status);
    audit_copy_field(finding.evidence, sizeof(finding.evidence), message);
    (void)audit_finding_add(&finding);
}

int audit_printf(const char *format, ...) {
    if (format == NULL)
        return -1;

    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    char rendered[2048];
    int rendered_length = vsnprintf(rendered, sizeof(rendered), format, copy);
    va_end(copy);
    if (rendered_length >= 0)
        audit_record_legacy_output(rendered);

    if (audit_json_output) {
        va_end(args);
        return rendered_length < 0 ? -1 : rendered_length;
    }
    if (audit_color_enabled()) {
        int result = vfprintf(stdout, format, args);
        va_end(args);
        return result;
    }

    size_t length = strlen(format);
    char *plain = malloc(length + 1);
    if (plain == NULL) {
        va_end(args);
        return -1;
    }

    size_t source = 0;
    size_t target = 0;
    while (source < length) {
        if ((unsigned char)format[source] == 0x1b &&
            source + 1 < length && format[source + 1] == '[') {
            source += 2;
            while (source < length &&
                   !((unsigned char)format[source] >= 0x40 &&
                     (unsigned char)format[source] <= 0x7e))
                source++;
            if (source < length)
                source++;
            continue;
        }
        plain[target++] = format[source++];
    }
    plain[target] = '\0';
    int result = vfprintf(stdout, plain, args);
    free(plain);
    va_end(args);
    return result;
}

int audit_has_mount_option(const char *options, const char *wanted) {
    if (options == NULL || wanted == NULL || wanted[0] == '\0')
        return 0;

    size_t wanted_length = strlen(wanted);
    const char *cursor = options;
    while (*cursor != '\0') {
        const char *end = strchr(cursor, ',');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (length == wanted_length && strncmp(cursor, wanted, length) == 0)
            return 1;
        if (end == NULL)
            break;
        cursor = end + 1;
    }
    return 0;
}

int audit_parse_int(const char *text, int *value) {
    if (text == NULL || value == NULL || text[0] == '\0')
        return -1;

    errno = 0;
    char *end = NULL;
    long parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || parsed < INT_MIN || parsed > INT_MAX)
        return -1;
    while (isspace((unsigned char)*end))
        end++;
    if (*end != '\0')
        return -1;

    *value = (int)parsed;
    return 0;
}

int audit_read_config_line(FILE *stream, char *buffer, size_t size) {
    if (stream == NULL || buffer == NULL || size < 2 || size > INT_MAX)
        return -1;

    if (fgets(buffer, (int)size, stream) == NULL)
        return ferror(stream) ? -1 : 0;

    size_t length = strlen(buffer);
    if (length > 0 && buffer[length - 1] != '\n' && !feof(stream)) {
        int ch;
        while ((ch = fgetc(stream)) != '\n' && ch != EOF)
            ;
        return ferror(stream) ? -1 : -2;
    }

    if (length > 0 && buffer[length - 1] == '\n')
        buffer[--length] = '\0';
    if (length > 0 && buffer[length - 1] == '\r')
        buffer[--length] = '\0';
    return 1;
}

char *audit_trim(char *text) {
    if (text == NULL)
        return NULL;

    while (isspace((unsigned char)*text))
        text++;

    size_t length = strlen(text);
    while (length > 0 && isspace((unsigned char)text[length - 1]))
        text[--length] = '\0';
    return text;
}

int audit_config_line_is_active(const char *line) {
    if (line == NULL)
        return 0;

    while (isspace((unsigned char)*line))
        line++;
    return *line != '\0' && *line != '#';
}

int audit_config_has_directive(FILE *stream, const char *directive, int require_value) {
    if (stream == NULL || directive == NULL || directive[0] == '\0')
        return -1;

    char line[1024];
    int status;
    while ((status = audit_read_config_line(stream, line, sizeof(line))) == 1) {
        char *active = audit_trim(line);
        if (!audit_config_line_is_active(active))
            continue;

        char *comment = strchr(active, '#');
        if (comment != NULL)
            *comment = '\0';
        active = audit_trim(active);

        char *end = active;
        while (*end != '\0' && !isspace((unsigned char)*end) && *end != '=')
            end++;
        size_t key_length = (size_t)(end - active);
        if (key_length != strlen(directive) ||
            strncmp(active, directive, key_length) != 0)
            continue;

        if (!require_value)
            return 1;

        while (isspace((unsigned char)*end))
            end++;
        if (*end == '=') {
            end++;
            while (isspace((unsigned char)*end))
                end++;
        }
        if (*audit_trim(end) != '\0')
            return 1;
    }
    return status == 0 ? 0 : -1;
}

int audit_hosts_deny_all(FILE *stream) {
    if (stream == NULL)
        return -1;

    char line[1024];
    int status;
    while ((status = audit_read_config_line(stream, line, sizeof(line))) == 1) {
        char *comment = strchr(line, '#');
        if (comment != NULL)
            *comment = '\0';
        char *active = audit_trim(line);
        if (*active == '\0')
            continue;

        char *colon = strchr(active, ':');
        if (colon == NULL)
            continue;
        *colon = '\0';

        char *service = audit_trim(active);
        char *clients = audit_trim(colon + 1);
        if (strcmp(service, "ALL") != 0)
            continue;

        char *end = clients;
        while (*end != '\0' && !isspace((unsigned char)*end) && *end != ',')
            end++;
        if ((size_t)(end - clients) == 3 && strncmp(clients, "ALL", 3) == 0 &&
            *end == '\0')
            return 1;
    }
    return status == 0 ? 0 : -1;
}

int audit_shadow_has_empty_password(FILE *stream) {
    if (stream == NULL)
        return -1;

    char line[1024];
    int found = 0;
    int status;
    while ((status = audit_read_config_line(stream, line, sizeof(line))) == 1) {
        char *first = strchr(line, ':');
        char *second = first ? strchr(first + 1, ':') : NULL;
        if (first == NULL || second == NULL)
            return -1;
        if (second == first + 1)
            found = 1;
    }
    return status == 0 ? found : -1;
}

int audit_module_is_loaded(FILE *stream, const char *module_name) {
    if (stream == NULL || module_name == NULL || module_name[0] == '\0')
        return -1;

    char line[512];
    int status;
    while ((status = audit_read_config_line(stream, line, sizeof(line))) == 1) {
        char name[128];
        if (sscanf(line, "%127s", name) != 1)
            return -1;
        if (strcmp(name, module_name) == 0)
            return 1;
    }
    return status == 0 ? 0 : -1;
}

int audit_is_executable(const char *path) {
    struct stat st;
    if (path == NULL || stat(path, &st) != 0)
        return 0;
    return (st.st_mode & S_IXUSR) != 0;
}

static int audit_deadline_after(unsigned int timeout_ms, struct timespec *deadline) {
    if (timeout_ms == 0 || clock_gettime(CLOCK_MONOTONIC, deadline) != 0)
        return -1;
    deadline->tv_sec += (time_t)(timeout_ms / 1000U);
    deadline->tv_nsec += (long)(timeout_ms % 1000U) * 1000000L;
    if (deadline->tv_nsec >= 1000000000L) {
        deadline->tv_sec++;
        deadline->tv_nsec -= 1000000000L;
    }
    return 0;
}

static int audit_remaining_ms(const struct timespec *deadline) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    time_t seconds = deadline->tv_sec - now.tv_sec;
    long nanoseconds = deadline->tv_nsec - now.tv_nsec;
    if (nanoseconds < 0) {
        seconds--;
        nanoseconds += 1000000000L;
    }
    if (seconds < 0 || (seconds == 0 && nanoseconds <= 0))
        return 0;
    if (seconds > INT_MAX / 1000)
        return INT_MAX;
    long long milliseconds = (long long)seconds * 1000LL +
                             (nanoseconds + 999999L) / 1000000L;
    return milliseconds > INT_MAX ? INT_MAX : (int)milliseconds;
}

static void audit_prepare_child_process(void) {
    (void)setpgid(0, 0);
}

static void audit_prepare_parent_process(pid_t child) {
    /* The child also calls setpgid() before exec to close the fork/exec race. */
    (void)setpgid(child, child);
}

static int audit_kill_and_reap(pid_t child) {
    if (kill(-child, SIGKILL) != 0)
        (void)kill(child, SIGKILL);
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        return -1;
    }
    return 0;
}

static int audit_wait_for_child_until(pid_t child, const struct timespec *deadline) {
    for (;;) {
        int status;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
            return -1;
        }
        if (result < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        int remaining = audit_remaining_ms(deadline);
        if (remaining <= 0) {
            (void)audit_kill_and_reap(child);
            return remaining == 0 ? -3 : -1;
        }
        struct timespec pause = {0, 10000000L};
        if (remaining < 10)
            pause.tv_nsec = (long)remaining * 1000000L;
        while (nanosleep(&pause, &pause) != 0 && errno == EINTR)
            ;
    }
}

int audit_run_command_timeout(const char *const argv[], int suppress_output,
                              unsigned int timeout_ms) {
    if (argv == NULL || argv[0] == NULL || argv[0][0] == '\0')
        return -1;
    struct timespec deadline;
    if (audit_deadline_after(timeout_ms, &deadline) != 0)
        return -1;

    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        audit_prepare_child_process();
        if (suppress_output) {
            int null_fd = open("/dev/null", O_WRONLY);
            if (null_fd >= 0) {
                (void)dup2(null_fd, STDOUT_FILENO);
                (void)dup2(null_fd, STDERR_FILENO);
                if (null_fd > STDERR_FILENO) close(null_fd);
            }
        }
        if (setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) != 0)
            _exit(126);
        execvp(argv[0], (char *const *)argv);
        _exit(errno == ENOENT ? 127 : 126);
    }
    audit_prepare_parent_process(child);
    return audit_wait_for_child_until(child, &deadline);
}

int audit_capture_command_timeout(const char *const argv[], char *output,
                                  size_t output_size, unsigned int timeout_ms) {
    if (argv == NULL || argv[0] == NULL || argv[0][0] == '\0' ||
        output == NULL || output_size == 0)
        return -1;
    struct timespec deadline;
    if (audit_deadline_after(timeout_ms, &deadline) != 0)
        return -1;

    output[0] = '\0';
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t child = fork();
    if (child < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (child == 0) {
        audit_prepare_child_process();
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0)
            _exit(126);
        close(fds[1]);
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            (void)dup2(null_fd, STDERR_FILENO);
            if (null_fd > STDERR_FILENO) close(null_fd);
        }
        if (setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) != 0)
            _exit(126);
        execvp(argv[0], (char *const *)argv);
        _exit(errno == ENOENT ? 127 : 126);
    }

    audit_prepare_parent_process(child);
    close(fds[1]);
    size_t used = 0;
    int truncated = 0;
    char chunk[4096];
    for (;;) {
        int remaining = audit_remaining_ms(&deadline);
        if (remaining <= 0) {
            close(fds[0]);
            (void)audit_kill_and_reap(child);
            output[used] = '\0';
            return remaining == 0 ? -3 : -1;
        }
        struct pollfd descriptor = {fds[0], POLLIN | POLLHUP, 0};
        int ready = poll(&descriptor, 1, remaining);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            close(fds[0]);
            (void)audit_kill_and_reap(child);
            output[used] = '\0';
            return -1;
        }
        if (ready == 0) {
            close(fds[0]);
            (void)audit_kill_and_reap(child);
            output[used] = '\0';
            return -3;
        }
        ssize_t count = read(fds[0], chunk, sizeof(chunk));
        if (count == 0)
            break;
        if (count < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            close(fds[0]);
            (void)audit_kill_and_reap(child);
            output[used] = '\0';
            return -1;
        }
        size_t available = output_size - 1 - used;
        size_t copy_count = (size_t)count < available ? (size_t)count : available;
        if (copy_count != 0) {
            memcpy(output + used, chunk, copy_count);
            used += copy_count;
        }
        if (copy_count < (size_t)count)
            truncated = 1;
    }
    close(fds[0]);
    output[used] = '\0';
    int status = audit_wait_for_child_until(child, &deadline);
    if (status < 0)
        return status;
    if (truncated)
        return -2;
    return status;
}

int audit_run_command(const char *const argv[], int suppress_output) {
    return audit_run_command_timeout(argv, suppress_output,
                                     AUDIT_COMMAND_DEFAULT_TIMEOUT_MS);
}

int audit_capture_command(const char *const argv[], char *output, size_t output_size) {
    return audit_capture_command_timeout(argv, output, output_size,
                                         AUDIT_COMMAND_DEFAULT_TIMEOUT_MS);
}

int audit_config_value_equals(const char *config, const char *key, const char *expected) {
    if (config == NULL || key == NULL || key[0] == '\0' || expected == NULL)
        return -1;

    char *copy = strdup(config);
    if (copy == NULL)
        return -1;

    int found = 0;
    int matches = 0;
    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save);
         line != NULL; line = strtok_r(NULL, "\n", &save)) {
        char *active = audit_trim(line);
        if (*active == '\0' || *active == '#')
            continue;

        char *value = active;
        while (*value != '\0' && !isspace((unsigned char)*value))
            value++;
        if (*value == '\0')
            continue;
        *value++ = '\0';
        if (strcasecmp(active, key) != 0)
            continue;

        value = audit_trim(value);
        found++;
        if (strcmp(value, expected) == 0)
            matches++;
    }

    free(copy);
    if (found > 1)
        return -1;
    if (found == 0)
        return 0;
    return matches == 1 ? 1 : 0;
}
