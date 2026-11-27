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

#endif
