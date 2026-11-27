#include "audit_utils.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

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

int audit_shadow_has_empty_password(FILE *stream) {
    if (stream == NULL)
        return -1;

    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), stream) != NULL) {
        char *first = strchr(line, ':');
        char *second = first ? strchr(first + 1, ':') : NULL;
        if (first == NULL || second == NULL)
            return -1;
        if (second == first + 1)
            found = 1;
    }
    return ferror(stream) ? -1 : found;
}

int audit_module_is_loaded(FILE *stream, const char *module_name) {
    if (stream == NULL || module_name == NULL || module_name[0] == '\0')
        return -1;

    char line[512];
    while (fgets(line, sizeof(line), stream) != NULL) {
        char name[128];
        if (sscanf(line, "%127s", name) != 1)
            return -1;
        if (strcmp(name, module_name) == 0)
            return 1;
    }
    return ferror(stream) ? -1 : 0;
}

int audit_is_executable(const char *path) {
    struct stat st;
    if (path == NULL || stat(path, &st) != 0)
        return 0;
    return (st.st_mode & S_IXUSR) != 0;
}
