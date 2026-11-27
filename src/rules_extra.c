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
#include <limits.h>
#include "rules.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define COLOR_GREEN "\033[1;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

static int read_sysctl_int(const char *path, int *value) {
   FILE *f = fopen(path, "r");
   if (!f) return -1;
   char buf[64];
   if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
   fclose(f);
   char *end = NULL;
   errno = 0;
   long parsed = strtol(buf, &end, 10);
   if (errno != 0 || end == buf) return -1;
   while (*end == ' ' || *end == '\\t' || *end == '\\r' || *end == '\\n') end++;
   if (*end != '\\0' || parsed < INT_MIN || parsed > INT_MAX) return -1;
   *value = (int)parsed;
   return 0;
}

static int is_executable(const char *path) {
   struct stat st;
   if (stat(path, &st) != 0) return 0;
   return (st.st_mode & S_IXUSR) != 0;
}

void check_slackpkg_installed() {
   printf("\n[Slackware] Checking if slackpkg is installed and configured... ");
   if (access("/usr/sbin/slackpkg", X_OK) != 0 && access("/sbin/slackpkg", X_OK) != 0) {
      printf(COLOR_YELLOW "Notice: slackpkg binary not found.\n" COLOR_RESET); return;
   }
   if (access("/etc/slackpkg/slackpkg.conf", R_OK) != 0) {
      printf(COLOR_RED "FAILED! /etc/slackpkg/slackpkg.conf missing.\n" COLOR_RESET); return;
   }
   printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
}

void check_package_update_age() {
   printf("\n[Slackware] Checking package database freshness... ");
   DIR *dir = opendir("/var/log/packages");
   if (!dir) { printf(COLOR_YELLOW "Notice: /var/log/packages not accessible.\n" COLOR_RESET); return; }
   time_t newest = 0;
   struct dirent *ent;
   while ((ent = readdir(dir)) != NULL) {
      if (ent->d_name[0] == '.') continue;
      char path[PATH_MAX];
      snprintf(path, sizeof(path), "/var/log/packages/%s", ent->d_name);
      struct stat st;
      if (stat(path, &st) == 0 && st.st_mtime > newest) newest = st.st_mtime;
   }
   closedir(dir);
   if (newest == 0) { printf(COLOR_YELLOW "Notice: No package records.\n" COLOR_RESET); return; }
   double days = difftime(time(NULL), newest) / 86400.0;
   if (days > 60.0) printf(COLOR_RED "FAILED! Newest package record is %.0f days old (>60).\n" COLOR_RESET, days);
   else if (days > 30.0) printf(COLOR_YELLOW "Notice: Newest package record is %.0f days old (>30).\n" COLOR_RESET, days);
   else printf(COLOR_GREEN "PASSED! Newest package record is %.0f days old.\n" COLOR_RESET, days);
}

void check_packages_dir_permissions() {
   printf("\n[Slackware] Checking /var/log/packages permissions... ");
   const char *dirs[] = {"/var/log/packages", "/var/log/removed_packages", NULL};
   int issues = 0;
   for (int i = 0; dirs[i]; i++) {
      struct stat st;
      if (stat(dirs[i], &st) != 0) continue;
      if (st.st_uid != 0) { printf(COLOR_RED "\n  FAILED! %s not root-owned.\n" COLOR_RESET, dirs[i]); issues = 1; }
      if (st.st_mode & (S_IWOTH | S_IWGRP)) { printf(COLOR_RED "\n  FAILED! %s is group/world-writable.\n" COLOR_RESET, dirs[i]); issues = 1; }
   }
   if (!issues) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
}

void check_rc_d_enabled_services() {
   printf("\n[Slackware] Enumerating executable rc.d scripts...\n");
   DIR *dir = opendir("/etc/rc.d");
   if (!dir) { printf(COLOR_YELLOW "  Notice: /etc/rc.d not accessible.\n" COLOR_RESET); return; }
   int count = 0;
   struct dirent *ent;
   while ((ent = readdir(dir)) != NULL) {
      if (strncmp(ent->d_name, "rc.", 3) != 0) continue;
      char path[PATH_MAX];
      snprintf(path, sizeof(path), "/etc/rc.d/%s", ent->d_name);
      if (is_executable(path)) { printf("  [enabled] %s\n", ent->d_name); count++; }
   }
   closedir(dir);
   printf("  Total enabled rc scripts: %d\n", count);
}

void check_high_risk_rc_services() {
   printf("\n[Slackware] Checking high-risk rc.d scripts...\n");
   const char *risky[] = {"rc.gpm", "rc.bluetooth", "rc.inetd", "rc.nfsd", "rc.samba", "rc.sendmail", "rc.httpd", NULL};
   for (int i = 0; risky[i]; i++) {
      char path[PATH_MAX];
      snprintf(path, sizeof(path), "/etc/rc.d/%s", risky[i]);
      if (access(path, F_OK) != 0) { printf("  %s: not present\n", risky[i]); continue; }
      if (is_executable(path))
         printf(COLOR_RED "  FAILED! %s is executable (enabled).\n" COLOR_RESET, risky[i]);
      else
         printf(COLOR_GREEN "  PASSED! %s is not executable.\n" COLOR_RESET, risky[i]);
   }
}

void check_rc_script_permissions() {
   printf("\n[Slackware] Checking rc.d script ownership/permissions... ");
   DIR *dir = opendir("/etc/rc.d");
   if (!dir) { printf(COLOR_YELLOW "Notice: /etc/rc.d not accessible.\n" COLOR_RESET); return; }
   int issues = 0;
   struct dirent *ent;
   while ((ent = readdir(dir)) != NULL) {
      if (ent->d_name[0] == '.') continue;
      char path[PATH_MAX];
      snprintf(path, sizeof(path), "/etc/rc.d/%s", ent->d_name);
      struct stat st;
      if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
      if (st.st_uid != 0) { printf(COLOR_RED "\n  FAILED! %s not root-owned.\n" COLOR_RESET, path); issues = 1; }
      if (st.st_mode & S_IWOTH) { printf(COLOR_RED "\n  FAILED! %s is world-writable.\n" COLOR_RESET, path); issues = 1; }
   }
   closedir(dir);
   if (!issues) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
}

void check_rc_local_and_M() {
   printf("\n[Slackware] Reviewing rc.local and rc.M...\n");
   const char *files[] = {"/etc/rc.d/rc.local", "/etc/rc.d/rc.M", NULL};
   const char *bad[] = {"nc -l", "ncat -l", "python -c", "perl -e", "chmod 777", "base64 -d", NULL};
   for (int f = 0; files[f]; f++) {
      FILE *fp = fopen(files[f], "r");
      if (!fp) { printf("  %s: not present\n", files[f]); continue; }
      char line[512]; int ln = 0, found = 0;
      while (fgets(line, sizeof(line), fp)) {
         ln++;
         char *p = line; while (*p && isspace((unsigned char)*p)) p++;
         if (*p == '#' || *p == '\0') continue;
         for (int s = 0; bad[s]; s++) {
            if (strstr(p, bad[s])) {
               printf(COLOR_YELLOW "  Notice: %s:%d contains '%s'\n" COLOR_RESET, files[f], ln, bad[s]);
               found = 1;
            }
         }
      }
      fclose(fp);
      if (!found) printf(COLOR_GREEN "  %s: no high-risk patterns.\n" COLOR_RESET, files[f]);
   }
}

void check_lilo_password() {
   printf("\n[Slackware] Checking LILO password... ");
   FILE *fp = fopen("/etc/lilo.conf", "r");
   if (!fp) { printf(COLOR_YELLOW "Notice: /etc/lilo.conf not found.\n" COLOR_RESET); return; }
   int has_pw = 0, has_rest = 0; char line[256];
   while (fgets(line, sizeof(line), fp)) {
      if (line[0] == '#') continue;
      if (strstr(line, "password")) has_pw = 1;
      if (strstr(line, "restricted")) has_rest = 1;
   }
   fclose(fp);
   if (has_pw && has_rest) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   else if (has_pw) printf(COLOR_YELLOW "Notice: password set but restricted missing.\n" COLOR_RESET);
   else printf(COLOR_RED "FAILED! LILO password not configured.\n" COLOR_RESET);
}

void check_grub_password_enhanced() {
   printf("\n[Slackware] Checking GRUB password... ");
   const char *paths[] = {"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/efi/EFI/slackware/grub.cfg", NULL};
   FILE *fp = NULL;
   for (int i = 0; paths[i]; i++) { fp = fopen(paths[i], "r"); if (fp) break; }
   if (!fp) { printf(COLOR_YELLOW "Notice: No GRUB config found.\n" COLOR_RESET); return; }
   char line[512]; int found = 0;
   while (fgets(line, sizeof(line), fp)) {
      if (strstr(line, "password_pbkdf2") || strstr(line, "password ")) { found = 1; break; }
   }
   fclose(fp);
   if (found) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   else printf(COLOR_RED "FAILED! No GRUB password found.\n" COLOR_RESET);
}

void check_bootloader_config_permissions() {
   printf("\n[Slackware] Checking bootloader config permissions...\n");
   const char *files[] = {"/etc/lilo.conf", "/etc/elilo.conf", "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", NULL};
   for (int i = 0; files[i]; i++) {
      struct stat st;
      if (stat(files[i], &st) != 0) continue;
      mode_t mode = st.st_mode & 0777;
      if (st.st_uid != 0 || mode != 0600)
         printf(COLOR_RED "  FAILED! %s mode %o uid %d (want 0600 root).\n" COLOR_RESET, files[i], mode, (int)st.st_uid);
      else
         printf(COLOR_GREEN "  PASSED! %s is 0600 root.\n" COLOR_RESET, files[i]);
   }
}

void check_kernel_hardening_sysctls() {
   printf("\n[NSA/Slackware] Checking kernel hardening sysctls...\n");
   struct { const char *path; int min_v; int exact; const char *name; } c[] = {
      {"/proc/sys/kernel/kptr_restrict", 1, -1, "kernel.kptr_restrict"},
      {"/proc/sys/kernel/dmesg_restrict", 1, -1, "kernel.dmesg_restrict"},
      {"/proc/sys/kernel/yama/ptrace_scope", 1, -1, "kernel.yama.ptrace_scope"},
      {"/proc/sys/net/ipv4/conf/all/rp_filter", 1, -1, "net.ipv4.conf.all.rp_filter"},
      {"/proc/sys/net/ipv4/tcp_syncookies", 1, 1, "net.ipv4.tcp_syncookies"},
      {"/proc/sys/fs/protected_hardlinks", 1, 1, "fs.protected_hardlinks"},
      {"/proc/sys/fs/protected_symlinks", 1, 1, "fs.protected_symlinks"},
      {"/proc/sys/kernel/randomize_va_space", 2, 2, "kernel.randomize_va_space"},
      {NULL, 0, 0, NULL}
   };
   for (int i = 0; c[i].path; i++) {
      int val;
      if (read_sysctl_int(c[i].path, &val) != 0) {
         printf(COLOR_YELLOW "  Notice: cannot read %s\n" COLOR_RESET, c[i].name); continue;
      }
      int ok = (c[i].exact >= 0) ? (val == c[i].exact) : (val >= c[i].min_v);
      if (ok) printf(COLOR_GREEN "  PASSED! %s = %d\n" COLOR_RESET, c[i].name, val);
      else printf(COLOR_RED "  FAILED! %s = %d\n" COLOR_RESET, c[i].name, val);
   }
}

void check_unwanted_kernel_modules() {
   printf("\n[Slackware] Checking unwanted kernel modules...\n");
   const char *mods[] = {"firewire-core", "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf", NULL};
   FILE *fp = fopen("/proc/modules", "r");
   if (!fp) { printf(COLOR_YELLOW "  Notice: cannot read /proc/modules\n" COLOR_RESET); return; }
   char line[512], loaded[4096] = {0};
   while (fgets(line, sizeof(line), fp)) {
      char name[128];
      if (sscanf(line, "%127s", name) == 1) { strncat(loaded, name, sizeof(loaded)-strlen(loaded)-2); strcat(loaded, " "); }
   }
   fclose(fp);
   int any = 0;
   for (int i = 0; mods[i]; i++) {
      if (strstr(loaded, mods[i])) { printf(COLOR_RED "  FAILED! Module '%s' is loaded.\n" COLOR_RESET, mods[i]); any = 1; }
   }
   if (!any) printf(COLOR_GREEN "  PASSED! None of the listed modules are loaded.\n" COLOR_RESET);
}

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

void check_fstab_secure_options() {
   printf("\n[Slackware] Checking fstab secure options for tmp mounts...\n");
   FILE *fp = fopen("/etc/fstab", "r");
   if (!fp) { printf(COLOR_YELLOW "  Error: cannot read fstab\n" COLOR_RESET); return; }
   char line[512]; int checked = 0;
   while (fgets(line, sizeof(line), fp)) {
      if (line[0] == '#' || line[0] == '\n') continue;
      char fs[128], mount[128], type[64], opts[256];
      if (sscanf(line, "%127s %127s %63s %255s", fs, mount, type, opts) < 4) continue;
      if (strcmp(mount, "/tmp") == 0 || strcmp(mount, "/var/tmp") == 0 || strcmp(mount, "/dev/shm") == 0) {
         checked = 1;
         int ok = strstr(opts, "nodev") && strstr(opts, "nosuid") && strstr(opts, "noexec");
         if (ok) printf(COLOR_GREEN "  PASSED! %s has nodev,nosuid,noexec\n" COLOR_RESET, mount);
         else printf(COLOR_RED "  FAILED! %s options '%s'\n" COLOR_RESET, mount, opts);
      }
   }
   fclose(fp);
   if (!checked) printf(COLOR_YELLOW "  Notice: no dedicated /tmp|/var/tmp|/dev/shm in fstab.\n" COLOR_RESET);
}

void check_tmp_separation() {
   printf("\n[Slackware] Checking /tmp and /var/tmp mounts... ");
   FILE *fp = fopen("/proc/mounts", "r");
   if (!fp) { printf(COLOR_YELLOW "Error: cannot read /proc/mounts\n" COLOR_RESET); return; }
   int tmp_m = 0, vartmp_m = 0; char line[512];
   while (fgets(line, sizeof(line), fp)) {
      char fs[128], mount[128];
      if (sscanf(line, "%127s %127s", fs, mount) == 2) {
         if (strcmp(mount, "/tmp") == 0) tmp_m = 1;
         if (strcmp(mount, "/var/tmp") == 0) vartmp_m = 1;
      }
   }
   fclose(fp);
   if (tmp_m && vartmp_m) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   else printf(COLOR_YELLOW "Notice: /tmp separate=%d /var/tmp separate=%d\n" COLOR_RESET, tmp_m, vartmp_m);
}

void check_proc_hidepid() {
   printf("\n[Slackware] Checking hidepid on /proc... ");
   FILE *fp = fopen("/proc/mounts", "r");
   if (!fp) { printf(COLOR_YELLOW "Error reading mounts\n" COLOR_RESET); return; }
   int found = 0; char line[512];
   while (fgets(line, sizeof(line), fp)) {
      if (strstr(line, " /proc ") && strstr(line, "hidepid=2")) { found = 1; break; }
   }
   fclose(fp);
   if (found) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   else printf(COLOR_YELLOW "Notice: hidepid=2 not set on /proc.\n" COLOR_RESET);
}

void check_unexpected_world_writable_dirs() {
   printf("\n[Slackware] Scanning for unexpected world-writable dirs...\n");
   const char *roots[] = {"/etc", "/usr", "/var", "/opt", NULL};
   int issues = 0;
   for (int r = 0; roots[r]; r++) {
      DIR *d = opendir(roots[r]); if (!d) continue;
      struct dirent *ent;
      while ((ent = readdir(d)) != NULL) {
         if (ent->d_name[0] == '.') continue;
         char path[PATH_MAX];
         snprintf(path, sizeof(path), "%s/%s", roots[r], ent->d_name);
         struct stat st;
         if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
         if ((st.st_mode & S_IWOTH) && !(st.st_mode & 01000)) {
            if (strcmp(path, "/var/tmp") == 0 || strcmp(path, "/tmp") == 0) continue;
            printf(COLOR_RED "  FAILED! World-writable without sticky: %s\n" COLOR_RESET, path);
            issues = 1;
         }
      }
      closedir(d);
   }
   if (!issues) printf(COLOR_GREEN "  PASSED!\n" COLOR_RESET);
}

void check_listening_services() {
   printf("\n[Slackware] Checking listeners on 0.0.0.0 / ::...\n");
   int rc = system("command -v ss >/dev/null 2>&1 && ss -tuln 2>/dev/null | grep -E '0\\.0\\.0\\.0:|:::' >/tmp/ssc_listen.txt 2>/dev/null");
   if (rc != 0) rc = system("netstat -tuln 2>/dev/null | grep -E '0\\.0\\.0\\.0:|:::' >/tmp/ssc_listen.txt 2>/dev/null");
   FILE *fp = fopen("/tmp/ssc_listen.txt", "r");
   if (!fp) { printf(COLOR_YELLOW "  Notice: could not list listening sockets.\n" COLOR_RESET); return; }
   char line[256]; int count = 0;
   while (fgets(line, sizeof(line), fp)) { printf("  %s", line); count++; }
   fclose(fp); unlink("/tmp/ssc_listen.txt");
   if (count == 0) printf(COLOR_GREEN "  PASSED! No all-interface listeners.\n" COLOR_RESET);
   else printf(COLOR_YELLOW "  Notice: %d endpoint(s) on all interfaces.\n" COLOR_RESET, count);
}

void check_tcp_wrappers() {
   printf("\n[Slackware] Checking tcp_wrappers...\n");
   if (access("/etc/hosts.allow", F_OK) != 0 && access("/etc/hosts.deny", F_OK) != 0) {
      printf(COLOR_YELLOW "  Notice: neither hosts.allow nor hosts.deny present.\n" COLOR_RESET); return;
   }
   FILE *deny = fopen("/etc/hosts.deny", "r");
   int has_all = 0;
   if (deny) {
      char line[256];
      while (fgets(line, sizeof(line), deny)) {
         if (line[0] == '#') continue;
         if (strstr(line, "ALL: ALL") || strstr(line, "ALL : ALL")) { has_all = 1; break; }
      }
      fclose(deny);
   }
   if (has_all) printf(COLOR_GREEN "  PASSED! hosts.deny has ALL: ALL.\n" COLOR_RESET);
   else printf(COLOR_YELLOW "  Notice: no default ALL: ALL in hosts.deny.\n" COLOR_RESET);
}

void check_inetd_xinetd() {
   printf("\n[Slackware] Checking inetd/xinetd...\n");
   if (is_executable("/etc/rc.d/rc.inetd"))
      printf(COLOR_RED "  FAILED! rc.inetd is executable.\n" COLOR_RESET);
   else if (access("/etc/rc.d/rc.inetd", F_OK) == 0)
      printf(COLOR_GREEN "  PASSED! rc.inetd not executable.\n" COLOR_RESET);
   else
      printf(COLOR_GREEN "  PASSED! rc.inetd not present.\n" COLOR_RESET);
   if (access("/etc/xinetd.conf", F_OK) == 0 || access("/etc/xinetd.d", F_OK) == 0)
      printf(COLOR_YELLOW "  Notice: xinetd config present; review services.\n" COLOR_RESET);
}

void check_syslog_remote() {
   printf("\n[Slackware] Checking syslog remote reception...\n");
   const char *configs[] = {"/etc/syslog.conf", "/etc/rsyslog.conf", "/etc/syslog-ng/syslog-ng.conf", NULL};
   int found = 0;
   for (int i = 0; configs[i]; i++) {
      FILE *fp = fopen(configs[i], "r"); if (!fp) continue;
      found = 1; char line[512];
      while (fgets(line, sizeof(line), fp)) {
         if (line[0] == '#' || line[0] == '\n') continue;
         if ((strstr(line, "imudp") || strstr(line, "imtcp")) )
            printf(COLOR_YELLOW "  Notice: remote input module in %s\n" COLOR_RESET, configs[i]);
      }
      fclose(fp);
   }
   if (!found) printf(COLOR_YELLOW "  Notice: no common syslog config found.\n" COLOR_RESET);
   else printf(COLOR_GREEN "  (Review complete.)\n" COLOR_RESET);
}

void check_var_log_permissions() {
   printf("\n[Slackware] Checking /var/log permissions... ");
   struct stat st;
   if (stat("/var/log", &st) != 0) { printf(COLOR_YELLOW "Error: cannot stat /var/log\n" COLOR_RESET); return; }
   if (st.st_uid != 0) { printf(COLOR_RED "FAILED! not root-owned.\n" COLOR_RESET); return; }
   mode_t mode = st.st_mode & 0777;
   if (mode & S_IWOTH) printf(COLOR_RED "FAILED! world-writable.\n" COLOR_RESET);
   else printf(COLOR_GREEN "PASSED! mode %o root.\n" COLOR_RESET, mode);
}

void check_x11_nolisten() {
   printf("\n[Slackware] Checking X11 -nolisten tcp...\n");
   const char *files[] = {"/etc/X11/xinit/xserverrc", "/etc/X11/xdm/Xservers", NULL};
   int found = 0;
   for (int i = 0; files[i]; i++) {
      FILE *fp = fopen(files[i], "r"); if (!fp) continue;
      char line[256];
      while (fgets(line, sizeof(line), fp)) {
         if (strstr(line, "-nolisten tcp")) {
            printf(COLOR_GREEN "  PASSED! Found in %s\n" COLOR_RESET, files[i]); found = 1; break;
         }
      }
      fclose(fp); if (found) break;
   }
   if (!found) printf(COLOR_YELLOW "  Notice: -nolisten tcp not found in common locations.\n" COLOR_RESET);
}

void check_compiler_toolchains() {
   printf("\n[Slackware] Checking for compilers...\n");
   const char *c[] = {"/usr/bin/gcc", "/usr/bin/cc", "/usr/bin/clang", "/usr/bin/g++", "/usr/bin/make", NULL};
   int present = 0;
   for (int i = 0; c[i]; i++) {
      if (access(c[i], X_OK) == 0) { printf(COLOR_YELLOW "  Notice: %s present.\n" COLOR_RESET, c[i]); present = 1; }
   }
   if (!present) printf(COLOR_GREEN "  PASSED! No common compilers found.\n" COLOR_RESET);
}

void check_issue_files() {
   printf("\n[Slackware] Checking /etc/issue for version leakage...\n");
   const char *files[] = {"/etc/issue", "/etc/issue.net", NULL};
   for (int i = 0; files[i]; i++) {
      FILE *fp = fopen(files[i], "r");
      if (!fp) { printf("  %s: not present\n", files[i]); continue; }
      char buf[512]; size_t n = fread(buf, 1, sizeof(buf)-1, fp); buf[n] = '\0'; fclose(fp);
      if (strstr(buf, "Slackware") || strstr(buf, "Kernel") || strstr(buf, "release") || strstr(buf, "version"))
         printf(COLOR_YELLOW "  Notice: %s may leak version info.\n" COLOR_RESET, files[i]);
      else
         printf(COLOR_GREEN "  PASSED! %s looks clean.\n" COLOR_RESET, files[i]);
   }
}

void check_legacy_trust_files() {
   printf("\n[Slackware] Checking legacy trust files...\n");
   int issues = 0;
   if (access("/etc/hosts.equiv", F_OK) == 0) { printf(COLOR_RED "  FAILED! /etc/hosts.equiv exists.\n" COLOR_RESET); issues = 1; }
   DIR *d = opendir("/home");
   if (d) {
      struct dirent *ent;
      while ((ent = readdir(d)) != NULL) {
         if (ent->d_name[0] == '.') continue;
         char path[PATH_MAX];
         snprintf(path, sizeof(path), "/home/%s/.rhosts", ent->d_name);
         if (access(path, F_OK) == 0) { printf(COLOR_RED "  FAILED! %s exists.\n" COLOR_RESET, path); issues = 1; }
         snprintf(path, sizeof(path), "/home/%s/.netrc", ent->d_name);
         if (access(path, F_OK) == 0) { printf(COLOR_YELLOW "  Notice: %s exists.\n" COLOR_RESET, path); issues = 1; }
      }
      closedir(d);
   }
   if (access("/root/.rhosts", F_OK) == 0) { printf(COLOR_RED "  FAILED! /root/.rhosts exists.\n" COLOR_RESET); issues = 1; }
   if (access("/root/.netrc", F_OK) == 0) { printf(COLOR_YELLOW "  Notice: /root/.netrc exists.\n" COLOR_RESET); issues = 1; }
   if (!issues) printf(COLOR_GREEN "  PASSED!\n" COLOR_RESET);
}
