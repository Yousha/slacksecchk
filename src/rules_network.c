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

#define COLOR_GREEN "\033[1;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

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
