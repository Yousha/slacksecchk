#define _POSIX_C_SOURCE 200809L
#include "audit_utils.h"

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;

#define ASSERT_TRUE(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); failures++; \
} } while (0)

static FILE *fixture_stream(const char *contents) {
    FILE *stream = tmpfile();
    if (stream == NULL)
        return NULL;
    if (fputs(contents, stream) == EOF || fflush(stream) != 0 ||
        fseek(stream, 0, SEEK_SET) != 0) {
        fclose(stream);
        return NULL;
    }
    return stream;
}

static void test_executable_detection(void) {
    /* Arrange */
    char path[] = "/tmp/slacksecchk-executable-XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0);
    if (fd < 0)
        return;
    close(fd);

    /* Act / Assert */
    ASSERT_TRUE(chmod(path, 0700) == 0);
    ASSERT_TRUE(audit_is_executable(path) == 1);
    ASSERT_TRUE(chmod(path, 0600) == 0);
    ASSERT_TRUE(audit_is_executable(path) == 0);
    ASSERT_TRUE(audit_is_executable("/path/that/does/not/exist") == 0);

    /* Cleanup */
    ASSERT_TRUE(unlink(path) == 0);
}

static void test_mount_options(void) {
    /* Arrange */
    const char *options = "rw,nodev,nosuid,noexec";

    /* Act / Assert */
    ASSERT_TRUE(audit_has_mount_option(options, "nodev") == 1);
    ASSERT_TRUE(audit_has_mount_option(options, "nosuid") == 1);
    ASSERT_TRUE(audit_has_mount_option(options, "noexec") == 1);
    ASSERT_TRUE(audit_has_mount_option(options, "dev") == 0);
    ASSERT_TRUE(audit_has_mount_option(options, "exec") == 0);
    ASSERT_TRUE(audit_has_mount_option("rw,nodevish", "nodev") == 0);
    ASSERT_TRUE(audit_has_mount_option(NULL, "nodev") == 0);
    ASSERT_TRUE(audit_has_mount_option(options, "") == 0);
}

static void test_integer_parsing(void) {
    /* Arrange */
    int value = 99;

    /* Act / Assert */
    ASSERT_TRUE(audit_parse_int("0\n", &value) == 0 && value == 0);
    ASSERT_TRUE(audit_parse_int(" -12  ", &value) == 0 && value == -12);
    ASSERT_TRUE(audit_parse_int("2", &value) == 0 && value == 2);
    ASSERT_TRUE(audit_parse_int("", &value) == -1);
    ASSERT_TRUE(audit_parse_int("2x", &value) == -1);
    ASSERT_TRUE(audit_parse_int("999999999999999999999", &value) == -1);
    ASSERT_TRUE(audit_parse_int("1", NULL) == -1);
}

static void test_shadow_password_fields(void) {
    /* Arrange */
    FILE *safe = fixture_stream("root:$6$hash:19000:0:99999:7:::\nuser:!:19000:0:99999:7:::\n");
    FILE *empty = fixture_stream("root:$6$hash:19000:0:99999:7:::\nempty::19000:0:99999:7:::\n");
    FILE *malformed = fixture_stream("not-a-shadow-record\n");

    /* Act / Assert */
    ASSERT_TRUE(safe != NULL && audit_shadow_has_empty_password(safe) == 0);
    ASSERT_TRUE(empty != NULL && audit_shadow_has_empty_password(empty) == 1);
    ASSERT_TRUE(malformed != NULL && audit_shadow_has_empty_password(malformed) == -1);

    /* Cleanup */
    if (safe) fclose(safe);
    if (empty) fclose(empty);
    if (malformed) fclose(malformed);
}

static void test_module_name_matching(void) {
    /* Arrange */
    FILE *modules = fixture_stream("firewire_core 123 0 - Live 0x0\ncramfs 456 0 - Live 0x0\n");

    /* Act / Assert */
    ASSERT_TRUE(modules != NULL && audit_module_is_loaded(modules, "firewire_core") == 1);
    rewind(modules);
    ASSERT_TRUE(audit_module_is_loaded(modules, "firewire") == 0);
    rewind(modules);
    ASSERT_TRUE(audit_module_is_loaded(modules, "hfs") == 0);

    /* Cleanup */
    if (modules) fclose(modules);
}

static void test_config_line_reader(void) {
    /* Arrange */
    FILE *stream = fixture_stream("  key = value  \r\n# comment\nlast");
    char line[32];

    /* Act / Assert */
    ASSERT_TRUE(stream != NULL);
    ASSERT_TRUE(audit_read_config_line(stream, line, sizeof(line)) == 1);
    ASSERT_TRUE(strcmp(line, "  key = value  ") == 0);
    ASSERT_TRUE(audit_read_config_line(stream, line, sizeof(line)) == 1);
    ASSERT_TRUE(strcmp(line, "# comment") == 0);
    ASSERT_TRUE(audit_read_config_line(stream, line, sizeof(line)) == 1);
    ASSERT_TRUE(strcmp(line, "last") == 0);
    ASSERT_TRUE(audit_read_config_line(stream, line, sizeof(line)) == 0);

    /* Cleanup */
    if (stream) fclose(stream);
}

static void test_config_directives(void) {
    /* Arrange */
    FILE *config = fixture_stream(
        "  # password = commented\n"
        "password2 = not-the-password\n"
        "password = secret-hash\n"
        "restricted\n"
        "empty =   # no value\n");
    FILE *near_match = fixture_stream("password2 = not-a-password\n");

    /* Act / Assert */
    ASSERT_TRUE(config != NULL && near_match != NULL);
    ASSERT_TRUE(audit_config_has_directive(near_match, "password", 1) == 0);
    ASSERT_TRUE(audit_config_has_directive(config, "password", 1) == 1);
    rewind(config);
    ASSERT_TRUE(audit_config_has_directive(config, "password2", 1) == 1);
    rewind(config);
    ASSERT_TRUE(audit_config_has_directive(config, "restricted", 0) == 1);
    rewind(config);
    ASSERT_TRUE(audit_config_has_directive(config, "missing", 0) == 0);
    rewind(config);
    ASSERT_TRUE(audit_config_has_directive(config, "empty", 1) == 0);

    /* Cleanup */
    if (config) fclose(config);
    if (near_match) fclose(near_match);
}

static void test_hosts_deny_parser(void) {
    /* Arrange */
    FILE *safe = fixture_stream("  # ignored\n\nALL : ALL # deny all\n");
    FILE *partial = fixture_stream("LOCAL: ALL\nALL: 192.0.2.1\n");
    FILE *exception = fixture_stream("ALL: ALL EXCEPT 192.0.2.1\n");

    /* Act / Assert */
    ASSERT_TRUE(safe != NULL && audit_hosts_deny_all(safe) == 1);
    ASSERT_TRUE(partial != NULL && audit_hosts_deny_all(partial) == 0);
    ASSERT_TRUE(exception != NULL && audit_hosts_deny_all(exception) == 0);

    /* Cleanup */
    if (safe) fclose(safe);
    if (partial) fclose(partial);
    if (exception) fclose(exception);
}

static void test_overlong_config_line(void) {
    /* Arrange */
    char contents[1200];
    memset(contents, 'x', sizeof(contents) - 2);
    contents[sizeof(contents) - 2] = '\n';
    contents[sizeof(contents) - 1] = '\0';
    FILE *stream = fixture_stream(contents);
    FILE *shadow = fixture_stream(contents);
    FILE *modules = fixture_stream(contents);
    char line[16];

    /* Act / Assert */
    ASSERT_TRUE(stream != NULL && audit_read_config_line(stream, line, sizeof(line)) == -2);
    ASSERT_TRUE(shadow != NULL && audit_shadow_has_empty_password(shadow) == -1);
    ASSERT_TRUE(modules != NULL && audit_module_is_loaded(modules, "not-a-module") == -1);

    /* Cleanup */
    if (stream) fclose(stream);
    if (shadow) fclose(shadow);
    if (modules) fclose(modules);
}


static void test_safe_command_execution(void) {
    /* Arrange */
    const char *true_argv[] = {"/bin/true", NULL};
    const char *false_argv[] = {"/bin/false", NULL};
    const char *missing_argv[] = {"/definitely/not/a/real/command", NULL};
    const char *print_argv[] = {"/bin/printf", "%s", "literal;$(touch /tmp/slacksecchk-shell-injection)", NULL};
    const char *large_argv[] = {"/usr/bin/yes", "x", NULL};
    char output[128];

    /* Act / Assert */
    ASSERT_TRUE(audit_run_command(true_argv, 1) == 0);
    ASSERT_TRUE(audit_run_command(false_argv, 1) == 1);
    ASSERT_TRUE(audit_run_command(missing_argv, 1) == 127);
    ASSERT_TRUE(audit_capture_command(print_argv, output, sizeof(output)) == 0);
    ASSERT_TRUE(strcmp(output, "literal;$(touch /tmp/slacksecchk-shell-injection)") == 0);
    ASSERT_TRUE(access("/tmp/slacksecchk-shell-injection", F_OK) != 0);
    ASSERT_TRUE(audit_capture_command(large_argv, output, sizeof(output)) == -2);
    ASSERT_TRUE(audit_run_command(NULL, 1) == -1);
    ASSERT_TRUE(audit_capture_command(true_argv, NULL, sizeof(output)) == -1);
}

int main(void) {
    test_safe_command_execution();
    test_executable_detection();
    test_mount_options();
    test_integer_parsing();
    test_shadow_password_fields();
    test_module_name_matching();
    test_config_line_reader();
    test_config_directives();
    test_hosts_deny_parser();
    test_overlong_config_line();

    if (failures != 0) {
        fprintf(stderr, "%d assertion(s) failed.\n", failures);
        return EXIT_FAILURE;
    }
    puts("All audit utility tests passed.");
    return EXIT_SUCCESS;
}
