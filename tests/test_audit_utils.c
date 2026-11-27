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
    char marker[] = "/tmp/slacksecchk-shell-injection-XXXXXX";
    int marker_fd = mkstemp(marker);
    ASSERT_TRUE(marker_fd >= 0);
    if (marker_fd >= 0) close(marker_fd);
    ASSERT_TRUE(unlink(marker) == 0);
    char payload[256];
    snprintf(payload, sizeof(payload), "literal;$(touch %s)", marker);
    const char *true_argv[] = {"true", NULL};
    const char *capture_true_argv[] = {"true", NULL};
    const char *false_argv[] = {"/bin/false", NULL};
    const char *missing_argv[] = {"/definitely/not/a/real/command", NULL};
    const char *print_argv[] = {"/bin/printf", "%s", payload, NULL};
    const char *large_argv[] = {"/usr/bin/seq", "1", "1000", NULL};
    char output[128];
    char *old_path = getenv("PATH") ? strdup(getenv("PATH")) : NULL;

    /* Act / Assert */
    ASSERT_TRUE(setenv("PATH", "/tmp/slacksecchk-no-such-path", 1) == 0);
    ASSERT_TRUE(audit_run_command(true_argv, 1) == 0);
    ASSERT_TRUE(audit_capture_command(capture_true_argv, output, sizeof(output)) == 0);
    if (old_path != NULL) {
        ASSERT_TRUE(setenv("PATH", old_path, 1) == 0);
        free(old_path);
    } else {
        ASSERT_TRUE(unsetenv("PATH") == 0);
    }
    ASSERT_TRUE(audit_run_command(false_argv, 1) == 1);
    ASSERT_TRUE(audit_run_command(missing_argv, 1) == 127);
    ASSERT_TRUE(audit_capture_command(print_argv, output, sizeof(output)) == 0);
    ASSERT_TRUE(strcmp(output, payload) == 0);
    ASSERT_TRUE(access(marker, F_OK) != 0);
    ASSERT_TRUE(audit_capture_command(large_argv, output, sizeof(output)) == -2);
    ASSERT_TRUE(audit_run_command(NULL, 1) == -1);
    ASSERT_TRUE(audit_capture_command(true_argv, NULL, sizeof(output)) == -1);
    unlink(marker);
}


static void test_config_value_equals(void) {
    /* Arrange */
    const char *duplicate =
        "# generated configuration\n"
        "  PermitRootLogin   no  \n"
        "passwordauthentication yes\n"
        "MaxAuthTries 4\n"
        "PermitRootLogin yes\n";

    /* Act / Assert */
    ASSERT_TRUE(audit_config_value_equals(duplicate, "permitrootlogin", "no") == -1);
    ASSERT_TRUE(audit_config_value_equals("PermitRootLogin no\n", "permitrootlogin", "no") == 1);
    ASSERT_TRUE(audit_config_value_equals("PasswordAuthentication yes\n", "passwordauthentication", "no") == 0);
    ASSERT_TRUE(audit_config_value_equals("MaxAuthTries 4\n", "maxauthtries", "4") == 1);
    ASSERT_TRUE(audit_config_value_equals("MaxAuthTries 40\n", "maxauthtries", "4") == 0);
    ASSERT_TRUE(audit_config_value_equals("PermitRootLogin no\n", "permitroot", "no") == 0);
    ASSERT_TRUE(audit_config_value_equals("", "missing", "no") == 0);
    ASSERT_TRUE(audit_config_value_equals(NULL, "key", "value") == -1);
    ASSERT_TRUE(audit_config_value_equals("key value\n", NULL, "value") == -1);
}


static void test_structured_findings(void) {
    /* Arrange */
    audit_finding_t finding;
    audit_summary_t summary;
    FILE *stream = tmpfile();
    char output[2048];
    memset(&finding, 0, sizeof(finding));
    strcpy(finding.rule_id, "SSC-SSH-CONFIG");
    strcpy(finding.title, "SSH root login is enabled");
    strcpy(finding.description, "The effective SSH configuration permits root login.");
    strcpy(finding.severity, AUDIT_SEVERITY_HIGH);
    strcpy(finding.category, "accounts");
    strcpy(finding.status, AUDIT_STATUS_FAIL);
    strcpy(finding.evidence, "permitrootlogin yes");
    strcpy(finding.remediation, "Set PermitRootLogin no and reload sshd.");
    strcpy(finding.references, "CIS SSH server guidance");

    audit_reset_summary();

    /* Act */
    ASSERT_TRUE(audit_finding_add(&finding) == 0);
    ASSERT_TRUE(audit_finding_count() == 1);
    ASSERT_TRUE(audit_finding_get(0) != NULL);
    ASSERT_TRUE(audit_finding_get(1) == NULL);
    audit_get_summary(&summary);

    /* Assert */
    ASSERT_TRUE(summary.failed == 1);
    ASSERT_TRUE(summary.passed == 0 && summary.unverified == 0);
    ASSERT_TRUE(audit_summary_exit_code() == 1);
    ASSERT_TRUE(strcmp(audit_finding_get(0)->rule_id, "SSC-SSH-CONFIG") == 0);
    ASSERT_TRUE(stream != NULL);
    if (stream != NULL) {
        ASSERT_TRUE(audit_write_json_summary(stream, "1.1.0.0") == 0);
        ASSERT_TRUE(fflush(stream) == 0);
        ASSERT_TRUE(fseek(stream, 0, SEEK_SET) == 0);
        size_t count = fread(output, 1, sizeof(output) - 1, stream);
        output[count] = '\0';
        ASSERT_TRUE(strstr(output, "\"schema_version\":2") != NULL);
        ASSERT_TRUE(strstr(output, "\"rule_id\":\"SSC-SSH-CONFIG\"") != NULL);
        ASSERT_TRUE(strstr(output, "\"severity\":\"HIGH\"") != NULL);
        ASSERT_TRUE(strstr(output, "\"evidence\":\"permitrootlogin yes\"") != NULL);
        ASSERT_TRUE(strstr(output, "\"remediation\":\"Set PermitRootLogin no and reload sshd.\"") != NULL);
        fclose(stream);
    }

    finding.status[0] = '\0';
    ASSERT_TRUE(audit_finding_add(&finding) == -1);
    ASSERT_TRUE(audit_finding_add(NULL) == -1);
    audit_reset_summary();
    ASSERT_TRUE(audit_finding_count() == 0);
}

static void test_sarif_report(void) {
    /* Arrange */
    audit_finding_t finding;
    FILE *stream = tmpfile();
    char output[4096];
    memset(&finding, 0, sizeof(finding));
    strcpy(finding.rule_id, "SSC-SSH-CONFIG");
    strcpy(finding.title, "SSH root login is enabled");
    strcpy(finding.description, "Root login is permitted.");
    strcpy(finding.severity, AUDIT_SEVERITY_HIGH);
    strcpy(finding.category, "accounts");
    strcpy(finding.status, AUDIT_STATUS_FAIL);
    strcpy(finding.evidence, "permitrootlogin yes");
    strcpy(finding.remediation, "Set PermitRootLogin no.");
    strcpy(finding.references, "CIS SSH guidance");
    audit_reset_summary();

    /* Act */
    ASSERT_TRUE(audit_finding_add(&finding) == 0);
    strcpy(finding.rule_id, "SSC-SSH-PASS");
    strcpy(finding.status, AUDIT_STATUS_PASS);
    strcpy(finding.severity, AUDIT_SEVERITY_INFO);
    ASSERT_TRUE(audit_finding_add(&finding) == 0);
    strcpy(finding.rule_id, "SSC-SSH-WARN");
    strcpy(finding.status, AUDIT_STATUS_WARN);
    strcpy(finding.severity, AUDIT_SEVERITY_MEDIUM);
    ASSERT_TRUE(audit_finding_add(&finding) == 0);

    /* Assert */
    ASSERT_TRUE(stream != NULL);
    if (stream != NULL) {
        ASSERT_TRUE(audit_write_sarif_report(stream, "1.1.0.0") == 0);
        ASSERT_TRUE(fflush(stream) == 0);
        ASSERT_TRUE(fseek(stream, 0, SEEK_SET) == 0);
        size_t count = fread(output, 1, sizeof(output) - 1, stream);
        output[count] = '\0';
        ASSERT_TRUE(strstr(output, "\"version\":\"2.1.0\"") != NULL);
        ASSERT_TRUE(strstr(output, "\"ruleId\":\"SSC-SSH-CONFIG\"") != NULL);
        ASSERT_TRUE(strstr(output, "\"level\":\"error\"") != NULL);
        ASSERT_TRUE(strstr(output, "\"level\":\"warning\"") != NULL);
        ASSERT_TRUE(strstr(output, "\"remediation\":\"Set PermitRootLogin no.\"") != NULL);
        ASSERT_TRUE(strstr(output, "\"ruleId\":\"SSC-SSH-PASS\"") == NULL);
        fclose(stream);
    }
    audit_reset_summary();
}

static void test_command_timeouts(void) {
    /* Arrange */
    const char *sleep_argv[] = {"/bin/sleep", "5", NULL};
    char output[32];

    /* Act / Assert */
    ASSERT_TRUE(audit_run_command_timeout(sleep_argv, 1, 100) == -3);
    ASSERT_TRUE(audit_capture_command_timeout(sleep_argv, output, sizeof(output), 100) == -3);
    ASSERT_TRUE(output[0] == '\0');
    ASSERT_TRUE(audit_run_command_timeout(sleep_argv, 1, 0) == -1);
    ASSERT_TRUE(audit_capture_command_timeout(sleep_argv, output, sizeof(output), 0) == -1);
}

static void test_json_result_summary(void) {
    /* Arrange */
    audit_summary_t summary;
    FILE *stream = tmpfile();
    char output[512];

    audit_reset_summary();
    audit_set_json_output(1);

    /* Act */
    audit_printf("PASSED!\n");
    audit_printf("FAILED!\n");
    audit_printf("Notice: incomplete\n");
    audit_printf("Error: unreadable\n");
    audit_get_summary(&summary);

    /* Assert */
    ASSERT_TRUE(summary.passed == 1);
    ASSERT_TRUE(summary.failed == 1);
    ASSERT_TRUE(summary.unverified == 2);
    ASSERT_TRUE(audit_summary_exit_code() == 1);
    ASSERT_TRUE(stream != NULL);
    if (stream != NULL) {
        ASSERT_TRUE(audit_write_json_summary(stream, "1.1\"\\release") == 0);
        ASSERT_TRUE(fflush(stream) == 0);
        ASSERT_TRUE(fseek(stream, 0, SEEK_SET) == 0);
        size_t count = fread(output, 1, sizeof(output) - 1, stream);
        output[count] = '\0';
        ASSERT_TRUE(strstr(output, "\"schema_version\":2") != NULL);
        ASSERT_TRUE(strstr(output, "\"version\":\"1.1\\\"\\\\release\"") != NULL);
        ASSERT_TRUE(strstr(output, "\"status\":\"failed\"") != NULL);
        ASSERT_TRUE(strstr(output, "\"passed\":1,\"failed\":1,\"unverified\":2") != NULL);
        fclose(stream);
    }

    audit_reset_summary();
    audit_printf("Notice: still incomplete\n");
    audit_get_summary(&summary);
    ASSERT_TRUE(summary.passed == 0 && summary.failed == 0 && summary.unverified == 1);
    ASSERT_TRUE(audit_summary_exit_code() == 2);

    audit_reset_summary();
    audit_get_summary(&summary);
    ASSERT_TRUE(audit_summary_exit_code() == 0);
    ASSERT_TRUE(summary.passed == 0 && summary.failed == 0 && summary.unverified == 0);
    audit_set_json_output(0);
}

int main(void) {
    test_structured_findings();
    test_sarif_report();
    test_json_result_summary();
    test_command_timeouts();
    test_config_value_equals();
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
