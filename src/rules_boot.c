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
