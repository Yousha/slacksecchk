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
