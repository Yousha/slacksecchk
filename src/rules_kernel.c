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

static int read_sysctl_int(const char *path, int *value) {
   FILE *fp = fopen(path, "r");
   if (!fp) return -1;
   char buffer[64];
   int result = -1;
   if (fgets(buffer, sizeof(buffer), fp) != NULL)
      result = audit_parse_int(buffer, value);
   if (ferror(fp)) result = -1;
   fclose(fp);
   return result;
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
      {"/proc/sys/kernel/unprivileged_bpf_disabled", 1, -1, "kernel.unprivileged_bpf_disabled"},
      {"/proc/sys/kernel/perf_event_paranoid", 2, -1, "kernel.perf_event_paranoid"},
      {"/proc/sys/net/core/bpf_jit_harden", 1, -1, "net.core.bpf_jit_harden"},
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

void check_unwanted_kernel_modules(void) {
   printf("\n[Slackware] Checking unwanted kernel modules...\n");
   const char *modules[] = {"firewire_core", "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf", NULL};
   int found = 0, errors = 0;
   for (int i = 0; modules[i] != NULL; i++) {
      FILE *fp = fopen("/proc/modules", "r");
      if (!fp) { errors++; continue; }
      int loaded = audit_module_is_loaded(fp, modules[i]);
      if (fclose(fp) != 0) errors++;
      if (loaded == 1) {
         printf(COLOR_RED "  FAILED! Module %s is loaded.\n" COLOR_RESET, modules[i]);
         found++;
      } else if (loaded < 0) {
         errors++;
      }
   }
   if (errors)
      printf(COLOR_YELLOW "  Notice: module inventory incomplete (%d error(s)).\n" COLOR_RESET, errors);
   else if (!found)
      printf(COLOR_GREEN "  PASSED! None of the listed modules are loaded.\n" COLOR_RESET);
}
