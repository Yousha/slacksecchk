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
