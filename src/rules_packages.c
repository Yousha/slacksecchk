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
