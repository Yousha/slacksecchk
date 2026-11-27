#define _POSIX_C_SOURCE 200809L
#include "audit_utils.h"

#include <stdio.h>
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

int main(void) {
    test_mount_options();
    test_integer_parsing();
    test_shadow_password_fields();
    test_module_name_matching();

    if (failures != 0) {
        fprintf(stderr, "%d assertion(s) failed.\n", failures);
        return EXIT_FAILURE;
    }
    puts("All audit utility tests passed.");
    return EXIT_SUCCESS;
}
