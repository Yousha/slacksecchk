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

/* Run argv directly without a shell. Return child exit code or -1 on error. */
int audit_run_command(const char *const argv[], int suppress_output);
/* Capture stdout. Return exit code, -1 on error, or -2 when output is truncated. */
int audit_capture_command(const char *const argv[], char *output, size_t output_size);

/* Compare one exact key/value pair in command-generated configuration text.
 * Return 1 for a match, 0 for missing/mismatched values, and -1 for invalid
 * arguments or duplicate keys.
 */
int audit_config_value_equals(const char *config, const char *key, const char *expected);

#endif
