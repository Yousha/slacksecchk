#ifndef AUDIT_UTILS_H
#define AUDIT_UTILS_H

#include <stdio.h>

/* Return 1 when an exact comma-delimited mount option exists, otherwise 0. */
int audit_has_mount_option(const char *options, const char *wanted);

/* Parse a complete base-10 integer string; return 0 on success, -1 on error. */
int audit_parse_int(const char *text, int *value);

/* Return 1 for an empty shadow password field, 0 when none exist, -1 on malformed or I/O error. */
int audit_shadow_has_empty_password(FILE *stream);

/* Return 1 when an exact module name is present in a /proc/modules-style stream. */
int audit_module_is_loaded(FILE *stream, const char *module_name);

/* Return 1 when the owner-execute bit is set, otherwise 0. */
int audit_is_executable(const char *path);

/*
 * Read one complete configuration line. Return 1 for a line, 0 at EOF,
 * -1 on I/O error, and -2 when the line exceeds the supplied buffer.
 * Newline and a trailing carriage return are removed.
 */
int audit_read_config_line(FILE *stream, char *buffer, size_t size);

/* Return a pointer to the first non-whitespace character and trim trailing whitespace. */
char *audit_trim(char *text);

/* Return 1 for an active (nonblank, noncomment) line, otherwise 0. */
int audit_config_line_is_active(const char *line);

/*
 * Search active configuration lines for an exact directive name.
 * require_value enforces a nonempty value after optional whitespace and '='.
 * Return 1 when found, 0 when absent, and -1 for malformed/overlong input or I/O error.
 */
int audit_config_has_directive(FILE *stream, const char *directive, int require_value);

/* Return 1 for an exact "ALL: ALL" hosts.deny rule, 0 when absent, -1 on read error. */
int audit_hosts_deny_all(FILE *stream);

/* Terminal color modes: automatic TTY detection, forced colors, or disabled. */
#define AUDIT_COLOR_AUTO 0
#define AUDIT_COLOR_ALWAYS 1
#define AUDIT_COLOR_NEVER 2
void audit_set_color_mode(int mode);
int audit_color_enabled(void);
int audit_printf(const char *format, ...);

/* Structured audit finding statuses. */
#define AUDIT_STATUS_PASS "PASS"
#define AUDIT_STATUS_FAIL "FAIL"
#define AUDIT_STATUS_WARN "WARN"
#define AUDIT_STATUS_INFO "INFO"
#define AUDIT_STATUS_NOT_APPLICABLE "NOT_APPLICABLE"
#define AUDIT_STATUS_ERROR "ERROR"

#define AUDIT_SEVERITY_INFO "INFO"
#define AUDIT_SEVERITY_LOW "LOW"
#define AUDIT_SEVERITY_MEDIUM "MEDIUM"
#define AUDIT_SEVERITY_HIGH "HIGH"
#define AUDIT_SEVERITY_CRITICAL "CRITICAL"

#define AUDIT_FINDING_MAX 512
#define AUDIT_RULE_ID_SIZE 64
#define AUDIT_TITLE_SIZE 160
#define AUDIT_DESCRIPTION_SIZE 512
#define AUDIT_SEVERITY_SIZE 16
#define AUDIT_CATEGORY_SIZE 64
#define AUDIT_STATUS_SIZE 20
#define AUDIT_EVIDENCE_SIZE 1024
#define AUDIT_REMEDIATION_SIZE 512
#define AUDIT_REFERENCES_SIZE 256

typedef struct {
    char rule_id[AUDIT_RULE_ID_SIZE];
    char title[AUDIT_TITLE_SIZE];
    char description[AUDIT_DESCRIPTION_SIZE];
    char severity[AUDIT_SEVERITY_SIZE];
    char category[AUDIT_CATEGORY_SIZE];
    char status[AUDIT_STATUS_SIZE];
    char evidence[AUDIT_EVIDENCE_SIZE];
    char remediation[AUDIT_REMEDIATION_SIZE];
    char references[AUDIT_REFERENCES_SIZE];
} audit_finding_t;

typedef struct {
    unsigned long passed;
    unsigned long failed;
    unsigned long unverified;
} audit_summary_t;

/* Set the stable rule identity used by legacy audit_printf result adapters. */
void audit_set_current_rule(const char *rule_id, const char *category);
/* Add a validated structured finding. Returns 0 on success, -1 on invalid input/capacity. */
int audit_finding_add(const audit_finding_t *finding);
/* Return the number of stored findings and a read-only finding by index. */
size_t audit_finding_count(void);
const audit_finding_t *audit_finding_get(size_t index);

void audit_reset_summary(void);
void audit_set_json_output(int enabled);
void audit_get_summary(audit_summary_t *summary);
int audit_summary_exit_code(void);
int audit_write_json_summary(FILE *stream, const char *version);

/* Default upper bound for commands invoked by audit checks. */
#define AUDIT_COMMAND_DEFAULT_TIMEOUT_MS 30000U

/* Timeout-aware process APIs: -1 error, -2 truncated capture, -3 timed out. */
int audit_run_command_timeout(const char *const argv[], int suppress_output, unsigned int timeout_ms);
int audit_capture_command_timeout(const char *const argv[], char *output, size_t output_size, unsigned int timeout_ms);

/* Run argv directly without a shell; applies the default command timeout. */
int audit_run_command(const char *const argv[], int suppress_output);
/* Capture stdout with the default command timeout. */
int audit_capture_command(const char *const argv[], char *output, size_t output_size);

/* Compare one exact key/value pair in command-generated configuration text.
 * Return 1 for a match, 0 for missing/mismatched values, and -1 for invalid
 * arguments or duplicate keys.
 */
int audit_config_value_equals(const char *config, const char *key, const char *expected);

#endif
