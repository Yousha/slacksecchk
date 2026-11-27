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
#define printf audit_printf

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define COLOR_GREEN "\033[1;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

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
         int ok = audit_has_mount_option(opts, "nodev") && audit_has_mount_option(opts, "nosuid") && audit_has_mount_option(opts, "noexec");
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
