#define _POSIX_C_SOURCE 200809L
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

void check_listening_services() {
   printf("\n[Slackware] Checking listeners on 0.0.0.0 / ::...\n");
   const char *ss_argv[] = {"ss", "-tuln", NULL};
   char output[65536];
   int status = audit_capture_command(ss_argv, output, sizeof(output));
   if (status != 0) {
      const char *netstat_argv[] = {"netstat", "-tuln", NULL};
      status = audit_capture_command(netstat_argv, output, sizeof(output));
   }
   if (status != 0) {
      printf(COLOR_YELLOW "  Notice: listener inventory unavailable or incomplete (exit %d).\n" COLOR_RESET, status);
      return;
   }
   int count = 0;
   char *save = NULL;
   for (char *line = strtok_r(output, "\n", &save); line != NULL;
        line = strtok_r(NULL, "\n", &save)) {
      if (strstr(line, "0.0.0.0:") || strstr(line, ":::") || strstr(line, "[::]:")) {
         printf("  %s\n", line);
         count++;
      }
   }
   if (count == 0) printf(COLOR_GREEN "  PASSED! No all-interface listeners.\n" COLOR_RESET);
   else printf(COLOR_YELLOW "  Notice: %d endpoint(s) on all interfaces.\n" COLOR_RESET, count);
}

void check_tcp_wrappers() {
   printf("\n[Slackware] Checking tcp_wrappers...\n");
   if (access("/etc/hosts.allow", F_OK) != 0 && access("/etc/hosts.deny", F_OK) != 0) {
      printf(COLOR_YELLOW "  Notice: neither hosts.allow nor hosts.deny present.\n" COLOR_RESET); return;
   }
   FILE *deny = fopen("/etc/hosts.deny", "r");
   if (!deny) {
      printf(COLOR_YELLOW "  Notice: /etc/hosts.deny cannot be read.\n" COLOR_RESET);
      return;
   }

   int has_all = audit_hosts_deny_all(deny);
   fclose(deny);
   if (has_all == 1)
      printf(COLOR_GREEN "  PASSED! hosts.deny has an exact ALL: ALL rule.\n" COLOR_RESET);
   else if (has_all == 0)
      printf(COLOR_YELLOW "  Notice: no exact ALL: ALL rule in hosts.deny.\n" COLOR_RESET);
   else
      printf(COLOR_YELLOW "  Notice: unable to parse hosts.deny completely.\n" COLOR_RESET);
}

void check_inetd_xinetd() {
   printf("\n[Slackware] Checking inetd/xinetd...\n");
   if (audit_is_executable("/etc/rc.d/rc.inetd"))
      printf(COLOR_RED "  FAILED! rc.inetd is executable.\n" COLOR_RESET);
   else if (access("/etc/rc.d/rc.inetd", F_OK) == 0)
      printf(COLOR_GREEN "  PASSED! rc.inetd not executable.\n" COLOR_RESET);
   else
      printf(COLOR_GREEN "  PASSED! rc.inetd not present.\n" COLOR_RESET);
   if (access("/etc/xinetd.conf", F_OK) == 0 || access("/etc/xinetd.d", F_OK) == 0)
      printf(COLOR_YELLOW "  Notice: xinetd config present; review services.\n" COLOR_RESET);
}
