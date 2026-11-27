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
