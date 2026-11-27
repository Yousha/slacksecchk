#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include "rules.h"
#include "audit_utils.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define COLOR_GREEN (audit_color_enabled() ? "\033[1;32m" : "")
#define COLOR_YELLOW (audit_color_enabled() ? "\033[1;33m" : "")
#define COLOR_RED (audit_color_enabled() ? "\033[1;31m" : "")
#define COLOR_RESET (audit_color_enabled() ? "\033[0m" : "")

void check_securetty() {
   printf("\n[Slackware] Checking /etc/securetty... ");
   FILE *fp = fopen("/etc/securetty", "r");
   if (!fp) { printf(COLOR_YELLOW "Notice: not found.\n" COLOR_RESET); return; }
   int has_tty = 0, has_pts = 0; char line[128];
   while (fgets(line, sizeof(line), fp)) {
      char *p = line; while (*p && isspace((unsigned char)*p)) p++;
      if (*p == '#' || *p == '\0') continue;
      if (strncmp(p, "tty", 3) == 0) has_tty = 1;
      if (strncmp(p, "pts/", 4) == 0) has_pts = 1;
   }
   fclose(fp);
   if (has_pts) printf(COLOR_RED "FAILED! pts allowed (network root login).\n" COLOR_RESET);
   else if (has_tty) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   else printf(COLOR_YELLOW "Notice: review /etc/securetty manually.\n" COLOR_RESET);
}

void check_login_defs() {
   printf("\n[Slackware] Checking /etc/login.defs aging...\n");
   FILE *fp = fopen("/etc/login.defs", "r");
   if (!fp) { printf(COLOR_YELLOW "  Notice: not found.\n" COLOR_RESET); return; }
   int max_d = -1, min_d = -1, warn = -1; char line[256];
   while (fgets(line, sizeof(line), fp)) {
      if (line[0] == '#' || line[0] == '\n') continue;
      sscanf(line, "PASS_MAX_DAYS %d", &max_d);
      sscanf(line, "PASS_MIN_DAYS %d", &min_d);
      sscanf(line, "PASS_WARN_AGE %d", &warn);
   }
   fclose(fp);
   if (max_d > 0 && max_d <= 365) printf(COLOR_GREEN "  PASSED! PASS_MAX_DAYS = %d\n" COLOR_RESET, max_d);
   else printf(COLOR_RED "  FAILED! PASS_MAX_DAYS = %d\n" COLOR_RESET, max_d);
   if (min_d >= 0) printf(COLOR_GREEN "  PASSED! PASS_MIN_DAYS = %d\n" COLOR_RESET, min_d);
   if (warn >= 7) printf(COLOR_GREEN "  PASSED! PASS_WARN_AGE = %d\n" COLOR_RESET, warn);
   else printf(COLOR_YELLOW "  Notice: PASS_WARN_AGE = %d\n" COLOR_RESET, warn);
}

void check_pam_password_quality() {
   printf("\n[Slackware] Checking PAM password quality...\n");
   const char *files[] = {"/etc/pam.d/system-auth", "/etc/pam.d/passwd", "/etc/pam.d/common-password", NULL};
   int found = 0;
   for (int i = 0; files[i]; i++) {
      FILE *fp = fopen(files[i], "r"); if (!fp) continue;
      char line[256];
      while (fgets(line, sizeof(line), fp)) {
         if (strstr(line, "pam_pwquality") || strstr(line, "pam_cracklib") || strstr(line, "pam_passwdqc")) {
            printf(COLOR_GREEN "  PASSED! Found in %s\n" COLOR_RESET, files[i]); found = 1; break;
         }
      }
      fclose(fp); if (found) break;
   }
   if (!found) printf(COLOR_YELLOW "  Notice: no pam_pwquality/cracklib/passwdqc found.\n" COLOR_RESET);
}

void check_uid0_users() {
   printf("\n[Slackware] Checking extra UID 0 accounts... ");
   FILE *fp = fopen("/etc/passwd", "r");
   if (!fp) { printf(COLOR_YELLOW "Error: cannot read /etc/passwd\n" COLOR_RESET); return; }
   char line[512]; int extra = 0;
   while (fgets(line, sizeof(line), fp)) {
      char user[64]; int uid;
      if (sscanf(line, "%63[^:]:%*[^:]:%d", user, &uid) == 2 && uid == 0 && strcmp(user, "root") != 0) {
         printf(COLOR_RED "\n  FAILED! Extra UID 0: %s\n" COLOR_RESET, user); extra = 1;
      }
   }
   fclose(fp);
   if (!extra) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
}

void check_empty_or_locked_shell_accounts() {
   printf("\n[Slackware] Checking empty passwords in shadow...\n");
   FILE *fp = fopen("/etc/shadow", "r");
   if (!fp) { printf(COLOR_YELLOW "  Notice: cannot read /etc/shadow (need root?).\n" COLOR_RESET); return; }
   int issues = 0; char line[512];
   while (fgets(line, sizeof(line), fp)) {
      char user[64], hash[256];
      if (sscanf(line, "%63[^:]:%255[^:]", user, hash) != 2) continue;
      if (hash[0] == '\0') { printf(COLOR_RED "  FAILED! Empty password: %s\n" COLOR_RESET, user); issues = 1; }
   }
   fclose(fp);
   if (!issues) printf(COLOR_GREEN "  PASSED!\n" COLOR_RESET);
}

void check_shells_file() {
   printf("\n[Slackware] Checking /etc/shells... ");
   FILE *fp = fopen("/etc/shells", "r");
   if (!fp) { printf(COLOR_YELLOW "Notice: not found.\n" COLOR_RESET); return; }
   int issues = 0; char line[256];
   while (fgets(line, sizeof(line), fp)) {
      char *p = line; while (*p && isspace((unsigned char)*p)) p++;
      if (*p == '#' || *p == '\0') continue;
      char *nl = strchr(p, '\n'); if (nl) *nl = '\0';
      if (access(p, X_OK) != 0) { printf(COLOR_YELLOW "\n  Notice: '%s' not executable.\n" COLOR_RESET, p); issues = 1; }
   }
   fclose(fp);
   if (!issues) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
}

void check_sudo_config() {
   printf("\n[Slackware] Checking sudo configuration...\n");
   if (access("/usr/bin/sudo", X_OK) != 0 && access("/etc/sudoers", R_OK) != 0) {
      printf(COLOR_YELLOW "  Notice: sudo not installed.\n" COLOR_RESET); return;
   }
   struct stat st;
   if (stat("/etc/sudoers", &st) == 0) {
      if (st.st_uid != 0 || (st.st_mode & 0777) != 0440)
         printf(COLOR_RED "  FAILED! /etc/sudoers should be 0440 root.\n" COLOR_RESET);
      else
         printf(COLOR_GREEN "  PASSED! /etc/sudoers permissions OK.\n" COLOR_RESET);
   }
   FILE *fp = fopen("/etc/sudoers", "r");
   if (fp) {
      char line[512];
      while (fgets(line, sizeof(line), fp)) {
         if (line[0] == '#') continue;
         if (strstr(line, "NOPASSWD") && strstr(line, "ALL"))
            printf(COLOR_YELLOW "  Notice: broad NOPASSWD rule in sudoers.\n" COLOR_RESET);
      }
      fclose(fp);
   }
}


void check_ssh_effective_config(void) {
   printf("\n[Slackware] Checking effective SSH daemon configuration...\n");
   const char *argv[] = {"sshd", "-T", NULL};
   char output[16384];
   int status = audit_capture_command(argv, output, sizeof(output));
   if (status != 0) {
      printf(COLOR_YELLOW "  Notice: effective sshd configuration is unavailable or incomplete (exit %d).\n" COLOR_RESET, status);
      return;
   }

   const struct { const char *key; const char *expected; } required[] = {
      {"permitrootlogin", "no"},
      {"passwordauthentication", "no"},
      {"permitemptypasswords", "no"},
      {"pubkeyauthentication", "yes"},
      {"x11forwarding", "no"},
      {"maxauthtries", "4"},
      {NULL, NULL}
   };
   for (int i = 0; required[i].key != NULL; i++) {
      int result = audit_config_value_equals(output, required[i].key, required[i].expected);
      if (result == 1)
         printf(COLOR_GREEN "  PASSED! %s = %s\n" COLOR_RESET, required[i].key, required[i].expected);
      else if (result == 0)
         printf(COLOR_RED "  FAILED! %s should be %s.\n" COLOR_RESET, required[i].key, required[i].expected);
      else
         printf(COLOR_YELLOW "  Notice: %s is duplicated or ambiguous in sshd output.\n" COLOR_RESET, required[i].key);
   }
}
