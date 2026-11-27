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
      if (audit_is_executable(path)) { printf("  [enabled] %s\n", ent->d_name); count++; }
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
      if (audit_is_executable(path))
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
