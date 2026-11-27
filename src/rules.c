#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include "rules.h"
#include "audit_utils.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// ANSI color codes for terminal output.
#define COLOR_GREEN "\033[1;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

void check_file_permissions(const char *filename, mode_t expected_mode) {
   printf("\n[CIS] Checking if file permission '%s' is secure... ", filename);
   struct stat file_stat;
   if (stat(filename, &file_stat) == 0) {
      if ((file_stat.st_mode & 0777) != expected_mode) {
         printf(COLOR_RED "FAILED! %s permissions are %o (should be %o)\n" COLOR_RESET, filename, file_stat.st_mode & 0777, expected_mode);
      } else {
         printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
      }
   } else {
      printf(COLOR_YELLOW "Error: Unable to access %s\n" COLOR_RESET, filename);
   }
}

void check_log_files(void) {
   check_file_permissions("/var/log/messages", 0600);
   check_file_permissions("/var/log/secure", 0600);
   check_file_permissions("/var/log/maillog", 0600);
   check_file_permissions("/var/log/syslog", 0640);
}

void check_password_policy() {
   printf("\n[CIS] Checking if password policy is enforced... ");
   FILE *file = fopen("/etc/security/pwquality.conf", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Notice: Password quality configuration file not found.\n" COLOR_RESET);
      return;
   }
   char line[256];
   int minlen_found = 0;
   while (fgets(line, sizeof(line), file)) {
      if (strstr(line, "minlen=")) {
         minlen_found = 1;
         printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
         break;
      }
   }
   if (!minlen_found) {
      printf(COLOR_RED "FAILED! Password policy (minlen) is not configured.\n" COLOR_RESET);
   }
   fclose(file);
}

void check_service(const char *service_name) {
   printf("\n[CIS] Checking if service '%s' is running... ", service_name);
   char command[256];
   snprintf(command, sizeof(command), "pgrep %s > /dev/null 2>&1", service_name);
   if (system(command) != 0) {
      printf(COLOR_RED "FAILED! Service '%s' is not running.\n" COLOR_RESET, service_name);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

void check_disabled_service(const char *service_name) {
   printf("\n[CIS] Checking if unnecessary service '%s' is disabled... ", service_name);
   char script_path[256];
   snprintf(script_path, sizeof(script_path), "/etc/rc.d/rc.%s", service_name);
   if (access(script_path, X_OK) == 0) {
      printf(COLOR_RED "FAILED! Unnecessary service '%s' is enabled.\n" COLOR_RESET, service_name);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

void check_user_password_expiration() {
   printf("\n[CIS] Checking password expiration for user accounts... ");
   (void)system("chage -l root | grep -E 'Password expires|Account expires' || echo '" COLOR_RED "FAILED! Could not verify password expiration for root." COLOR_RESET "'");
}

void check_firewall_rules(void) {
   printf("\n[CIS] Checking firewall configuration... ");
   FILE *fp = popen("iptables-save 2>/dev/null", "r");
   if (!fp) {
      printf(COLOR_YELLOW "Notice: iptables state unavailable; firewall is unverified.\n" COLOR_RESET);
      return;
   }
   char line[512];
   int has_filter = 0, has_input_rule = 0;
   while (fgets(line, sizeof(line), fp)) {
      if (!strncmp(line, "*filter", 7)) has_filter = 1;
      if (!strncmp(line, "-A INPUT ", 9) || !strncmp(line, "-A FORWARD ", 11))
         has_input_rule = 1;
   }
   int status = pclose(fp);
   if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
      printf(COLOR_YELLOW "Notice: iptables query failed; firewall is unverified.\n" COLOR_RESET);
   else if (!has_filter)
      printf(COLOR_YELLOW "Notice: no filter table was returned.\n" COLOR_RESET);
   else if (has_input_rule)
      printf(COLOR_GREEN "PASSED! Input/forward filter rules are present.\n" COLOR_RESET);
   else
      printf(COLOR_RED "FAILED! No INPUT or FORWARD rules were found.\n" COLOR_RESET);
}

void check_auditd() {
   printf("\n[CIS] Checking audit logging... ");
   if (system("service auditd status > /dev/null 2>&1") != 0) {
      printf(COLOR_RED "FAILED! auditd is not running.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

void check_access_control() {
   check_file_permissions("/etc", 0755);
   check_file_permissions("/root", 0700);
   check_file_permissions("/home", 0755);
}

void check_logging() {
   printf("\n[CIS] Checking logging configurations... ");
   if (system("service rsyslog status > /dev/null 2>&1") != 0 && system("service syslog-ng status > /dev/null 2>&1") != 0) {
      printf(COLOR_RED "FAILED! Logging service (rsyslog or syslog-ng) is not running.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
   printf("\n[CIS] Checking log rotation is configured...");
   if (access("/etc/logrotate.conf", F_OK) != 0) {
      printf(COLOR_YELLOW "Notice: Log rotation configuration not found.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

void check_services() {
   check_disabled_service("rpcbind");
   check_disabled_service("avahi-daemon");
   check_disabled_service("cups");
}

void check_unnecessary_packages() {
   const char *packages[] = {"nmap", "telnet", "vsftpd"};
   int failed = 0;
   for (int i = 0; i < (int)(sizeof(packages) / sizeof(packages[0])); i++) {
      printf("\n[CIS] Checking for unnecessary package '%s'... ", packages[i]);
      char command[256];
      snprintf(command, sizeof(command), "ls /var/log/packages | grep '^%s-' > /dev/null 2>&1", packages[i]);
      if (system(command) == 0) {
         printf(COLOR_RED "FAILED! Unnecessary package '%s' is installed.\n" COLOR_RESET, packages[i]);
         failed = 1;
      }
   }
   if (!failed) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

void check_umask_settings() {
   printf("\n[CIS] Checking umask settings... ");
   FILE *file = fopen("/etc/profile", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /etc/profile\n" COLOR_RESET);
      return;
   }
   char line[256];
   int umask_found = 0;
   while (fgets(line, sizeof(line), file)) {
      if (strstr(line, "umask 027")) {
         umask_found = 1;
         printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
         break;
      }
   }
   fclose(file);
   if (!umask_found) {
      printf(COLOR_RED "FAILED! Secure umask (027) is not configured in /etc/profile.\n" COLOR_RESET);
   }
}

void check_core_dumps() {
   printf("\n[CIS] Checking core dump settings... ");
   FILE *file = fopen("/etc/security/limits.conf", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /etc/security/limits.conf\n" COLOR_RESET);
      return;
   }
   char line[256];
   int core_dump_disabled = 0;
   while (fgets(line, sizeof(line), file)) {
      if (strstr(line, "* hard core 0")) {
         core_dump_disabled = 1;
         printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
         break;
      }
   }
   fclose(file);
   if (!core_dump_disabled) {
      printf(COLOR_RED "FAILED! Core dumps are not disabled in /etc/security/limits.conf.\n" COLOR_RESET);
   }
}

void check_ssh_config() {
   printf("\n[CIS] Checking SSH configuration... ");
   FILE *file = fopen("/etc/ssh/sshd_config", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /etc/ssh/sshd_config\n" COLOR_RESET);
      return;
   }
   char line[256];
   int root_login_disabled = 0, protocol_2_enabled = 0;
   while (fgets(line, sizeof(line), file)) {
      if (strstr(line, "PermitRootLogin no")) root_login_disabled = 1;
      if (strstr(line, "Protocol 2")) protocol_2_enabled = 1;
   }
   fclose(file);
   if (root_login_disabled && protocol_2_enabled) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! SSH is not configured securely.\n" COLOR_RESET);
   }
}

static int scan_permission_tree(const char *path, dev_t device, int scan_world_writable,
                                int *matches, int *errors) {
   struct stat st;
   if (lstat(path, &st) != 0) { (*errors)++; return -1; }
   if (st.st_dev != device || S_ISLNK(st.st_mode)) return 0;
   if (S_ISREG(st.st_mode)) {
      int match = scan_world_writable ? ((st.st_mode & S_IWOTH) != 0)
                                     : ((st.st_mode & (S_ISUID | S_ISGID)) != 0);
      if (match) { printf(COLOR_RED "  FAILED! %s\n" COLOR_RESET, path); (*matches)++; }
      return 0;
   }
   if (!S_ISDIR(st.st_mode)) return 0;
   DIR *dir = opendir(path);
   if (!dir) { (*errors)++; return -1; }
   struct dirent *entry;
   while ((entry = readdir(dir)) != NULL) {
      if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
      char child[PATH_MAX];
      int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
      if (n < 0 || (size_t)n >= sizeof(child)) { (*errors)++; continue; }
      scan_permission_tree(child, device, scan_world_writable, matches, errors);
   }
   if (closedir(dir) != 0) (*errors)++;
   return 0;
}

static void run_permission_scan(const char *label, int world_writable) {
   struct stat root;
   int matches = 0, errors = 0;
   printf("\n[CIS] Checking for %s...\n", label);
   if (getenv("SLACKSECCHK_TEST_MODE") != NULL) {
      printf(COLOR_YELLOW "Notice: filesystem scan skipped in test mode.\n" COLOR_RESET);
      return;
   }
   if (lstat("/", &root) != 0) {
      printf(COLOR_YELLOW "Notice: filesystem root cannot be inspected.\n" COLOR_RESET);
      return;
   }
   scan_permission_tree("/", root.st_dev, world_writable, &matches, &errors);
   if (errors)
      printf(COLOR_YELLOW "Notice: scan incomplete; %d filesystem error(s).\n" COLOR_RESET, errors);
   else if (!matches)
      printf(COLOR_GREEN "PASSED! No matching files found.\n" COLOR_RESET);
   else
      printf(COLOR_RED "FAILED! %d matching file(s) found.\n" COLOR_RESET, matches);
}

void check_world_writable_files(void) {
   run_permission_scan("world-writable files", 1);
}

void check_suid_sgid_files(void) {
   run_permission_scan("SUID/SGID files", 0);
}

void check_empty_passwords(void) {
   printf("\n[CIS] Checking for empty account password fields... ");
   FILE *fp = fopen("/etc/shadow", "r");
   if (!fp) {
      printf(COLOR_YELLOW "Notice: cannot read /etc/shadow; result is unverified.\n" COLOR_RESET);
      return;
   }
   int result = audit_shadow_has_empty_password(fp);
   fclose(fp);
   if (result == 1)
      printf(COLOR_RED "FAILED! Empty password field(s) found.\n" COLOR_RESET);
   else if (result == 0)
      printf(COLOR_GREEN "PASSED! No empty password fields found.\n" COLOR_RESET);
   else
      printf(COLOR_YELLOW "Notice: shadow audit incomplete or malformed.\n" COLOR_RESET);
}

void check_unused_kernel_modules() {
   printf("\n[CIS] Checking for unused kernel modules for servers... ");
   if (system("lsmod | grep -E 'usb_storage|firewire_core' > /dev/null 2>&1") == 0) {
      printf(COLOR_RED "FAILED! Unused kernel modules (usb_storage, firewire_core) are loaded.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

void check_sensitive_commands() {
   printf("\n[CIS] Checking access to sensitive commands... ");
   if (access("/etc/sudoers", F_OK) != 0) {
      printf(COLOR_YELLOW "Notice: /etc/sudoers file not found.\n" COLOR_RESET);
      return;
   }
   if (system("grep '^%%wheel' /etc/sudoers > /dev/null 2>&1") != 0) {
      printf(COLOR_RED "FAILED! Sensitive commands (sudo) are not properly restricted.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

void check_password_reuse_policy() {
   printf("\n[CIS] Checking password reuse policy... ");
   FILE *file = fopen("/etc/security/pwquality.conf", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /etc/security/pwquality.conf\n" COLOR_RESET);
      return;
   }
   char line[256];
   int remember_found = 0;
   while (fgets(line, sizeof(line), file)) {
      if (strstr(line, "remember=")) {
         remember_found = 1;
         printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
         break;
      }
   }
   fclose(file);
   if (!remember_found) {
      printf(COLOR_RED "FAILED! Password reuse policy is not configured.\n" COLOR_RESET);
   }
}

void check_cron_jobs(void) {
   const char *dirs[] = {"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                         "/etc/cron.monthly", "/etc/cron.weekly", NULL};
   int found = 0, errors = 0;
   printf("\n[CIS] Reviewing scheduled cron jobs...\n");
   for (int i = 0; dirs[i]; i++) {
      DIR *dir = opendir(dirs[i]);
      if (!dir) { if (errno != ENOENT) errors++; continue; }
      struct dirent *entry;
      while ((entry = readdir(dir)) != NULL) {
         if (entry->d_name[0] == '.') continue;
         char path[PATH_MAX];
         int n = snprintf(path, sizeof(path), "%s/%s", dirs[i], entry->d_name);
         struct stat st;
         if (n < 0 || (size_t)n >= sizeof(path) || lstat(path, &st) != 0) { errors++; continue; }
         if (S_ISREG(st.st_mode) && (st.st_mode & 0111)) {
            printf("  Review scheduled executable: %s\n", path);
            found++;
         }
      }
      if (closedir(dir) != 0) errors++;
   }
   if (errors)
      printf(COLOR_YELLOW "Notice: cron inventory incomplete (%d error(s)).\n" COLOR_RESET, errors);
   else if (found)
      printf(COLOR_YELLOW "Notice: %d scheduled executable(s) require policy review.\n" COLOR_RESET, found);
   else
      printf(COLOR_GREEN "PASSED! No executable cron files found in standard directories.\n" COLOR_RESET);
}

void check_time_synchronization() {
   printf("\n[CIS] Checking system time synchronization... ");
   if (system("service ntp status > /dev/null 2>&1") != 0 && system("service chronyd status > /dev/null 2>&1") != 0) {
      printf(COLOR_RED "FAILED! System time synchronization (NTP/Chrony) is not running.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

void check_selinux_apparmor() {
   printf("\n[CIS] Checking SELinux/AppArmor... ");
   FILE *file = fopen("/etc/selinux/config", "r");
   if (file != NULL) {
      char line[256];
      int enforcing_found = 0;
      while (fgets(line, sizeof(line), file)) {
         if (strstr(line, "SELINUX=enforcing")) {
            enforcing_found = 1;
            printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
            break;
         }
      }
      fclose(file);
      if (!enforcing_found) {
         printf(COLOR_RED "FAILED! SELinux is not enforcing.\n" COLOR_RESET);
      }
   } else if (access("/etc/apparmor.d", F_OK) == 0) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! Neither SELinux nor AppArmor is enabled.\n" COLOR_RESET);
   }
}

void check_usb_storage() {
   printf("\n[CIS] Checking USB storage devices... ");
   if (system("modprobe -n -v usb-storage | grep 'install /bin/true' > /dev/null 2>&1") != 0) {
      printf(COLOR_RED "FAILED! USB storage devices are not disabled.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

void check_open_ports(void) {
   printf("\n[CIS] Reviewing listening network sockets... ");
   FILE *fp = popen("ss -H -tuln 2>/dev/null", "r");
   if (!fp) {
      printf(COLOR_YELLOW "Notice: unable to query listening sockets.\n" COLOR_RESET);
      return;
   }
   char line[512];
   int count = 0;
   while (fgets(line, sizeof(line), fp)) {
      if (strstr(line, "0.0.0.0:") || strstr(line, "[::]:") || strstr(line, "*:")) {
         printf("Review listener: %s", line);
         count++;
      }
   }
   int status = pclose(fp);
   if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
      printf(COLOR_YELLOW "Notice: socket query failed; results may be incomplete.\n" COLOR_RESET);
   else if (!count)
      printf(COLOR_GREEN "PASSED! No wildcard-bound listeners were reported.\n" COLOR_RESET);
   else
      printf(COLOR_YELLOW "Notice: %d wildcard-bound listener(s) require policy review.\n" COLOR_RESET, count);
}

void check_bootloader_password() {
   printf("\n[CIS] Checking GRUB bootloader password... ");
   FILE *file = fopen("/boot/grub/grub.cfg", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Notice: GRUB bootloader configuration file not found.\n" COLOR_RESET);
      return;
   }
   char line[256];
   int password_found = 0;
   while (fgets(line, sizeof(line), file)) {
      if (strstr(line, "password")) {
         password_found = 1;
         printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
         break;
      }
   }
   fclose(file);
   if (!password_found) {
      printf(COLOR_RED "FAILED! GRUB bootloader password is not set.\n" COLOR_RESET);
   }
}

void check_secure_mount_options() {
   printf("\n[CIS] Checking secure mount options... ");
   FILE *file = fopen("/etc/fstab", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /etc/fstab\n" COLOR_RESET);
      return;
   }
   char line[256];
   int noexec_found = 0, nosuid_found = 0;
   while (fgets(line, sizeof(line), file)) {
      if (strstr(line, "noexec")) noexec_found = 1;
      if (strstr(line, "nosuid")) nosuid_found = 1;
   }
   fclose(file);
   if (noexec_found && nosuid_found) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! Secure mount options (noexec, nosuid) are not fully configured.\n" COLOR_RESET);
   }
}

void check_elilo_password() {
   printf("\n[CIS]: Checking if ELiLo bootloader has a password set... ");
   if (access("/boot/efi/EFI/elilo.efi", F_OK) != 0) {
      printf(COLOR_GREEN "PASSED! ELiLo bootloader not found.\n" COLOR_RESET);
      return;
   }
   FILE *file = fopen("/etc/elilo.conf", "r");
   if (file == NULL) {
      printf(COLOR_RED "FAILED! ELiLo bootloader is installed but config is missing.\n" COLOR_RESET);
      return;
   }
   char line[256];
   int password_found = 0;
   while (fgets(line, sizeof(line), file)) {
      if (strstr(line, "password")) { password_found = 1; break; }
   }
   fclose(file);
   if (password_found) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   else printf(COLOR_RED "FAILED! ELiLo bootloader does not have a password set.\n" COLOR_RESET);
}

void check_core_dump_restriction() {
   printf("\n[DISA STIG] Checking core dump restrictions... ");
   FILE *file = fopen("/etc/security/limits.conf", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /etc/security/limits.conf.\n" COLOR_RESET);
      return;
   }
   char line[256];
   int core_dump_disabled = 0;
   while (fgets(line, sizeof(line), file)) {
      if (strstr(line, "* hard core 0")) { core_dump_disabled = 1; break; }
   }
   fclose(file);
   if (core_dump_disabled) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   else printf(COLOR_RED "FAILED! Core dumps are not restricted in /etc/security/limits.conf.\n" COLOR_RESET);
}

void check_crypto_policy() {
   printf("\n[DISA STIG] Checking system-wide crypto policy enabled... ");
   FILE *file = fopen("/etc/crypto-policies/config", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /etc/crypto-policies/config.\n" COLOR_RESET);
      return;
   }
   fclose(file);
   printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
}

void check_ip_forwarding() {
   printf("\n[NSA] Checking if IP forwarding is disabled... ");
   FILE *file = fopen("/proc/sys/net/ipv4/ip_forward", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /proc/sys/net/ipv4/ip_forward.\n" COLOR_RESET);
      return;
   }
   char value[16];
   if (fgets(value, sizeof(value), file) == NULL) { fclose(file); printf(COLOR_YELLOW "Error reading value.\n" COLOR_RESET); return; }
   fclose(file);
   if (strcmp(value, "0\n") == 0) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   else printf(COLOR_RED "FAILED! IP forwarding is enabled.\n" COLOR_RESET);
}

void check_packet_redirection() {
   printf("\n[NSA] Checking if packet redirection is disabled... ");
   FILE *file = fopen("/proc/sys/net/ipv4/conf/all/send_redirects", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /proc/sys/net/ipv4/conf/all/send_redirects.\n" COLOR_RESET);
      return;
   }
   char value[16];
   if (fgets(value, sizeof(value), file) == NULL) { fclose(file); return; }
   fclose(file);
   if (strcmp(value, "0\n") == 0) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   else printf(COLOR_RED "FAILED! Packet redirection is enabled.\n" COLOR_RESET);
}

void check_source_routed_packets() {
   printf("\n[NSA] Checking if source routed packets are not accepted... ");
   FILE *file = fopen("/proc/sys/net/ipv4/conf/all/accept_source_route", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /proc/sys/net/ipv4/conf/all/accept_source_route.\n" COLOR_RESET);
      return;
   }
   char value[16];
   if (fgets(value, sizeof(value), file) == NULL) { fclose(file); return; }
   fclose(file);
   if (strcmp(value, "0\n") == 0) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   else printf(COLOR_RED "FAILED! Source routed packets are accepted.\n" COLOR_RESET);
}

void check_icmp_redirects() {
   printf("\n[NSA] Checking if ICMP redirects are not accepted... ");
   FILE *file = fopen("/proc/sys/net/ipv4/conf/all/accept_redirects", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /proc/sys/net/ipv4/conf/all/accept_redirects.\n" COLOR_RESET);
      return;
   }
   char value[16];
   if (fgets(value, sizeof(value), file) == NULL) { fclose(file); return; }
   fclose(file);
   if (strcmp(value, "0\n") == 0) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   else printf(COLOR_RED "FAILED! ICMP redirects are accepted.\n" COLOR_RESET);
}

void check_ipv6_router_advertisements() {
   printf("\n[NSA] Checking if IPv6 router advertisements are not accepted... ");
   FILE *file = fopen("/proc/sys/net/ipv6/conf/all/accept_ra", "r");
   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /proc/sys/net/ipv6/conf/all/accept_ra.\n" COLOR_RESET);
      return;
   }
   char value[16];
   if (fgets(value, sizeof(value), file) == NULL) { fclose(file); return; }
   fclose(file);
   if (strcmp(value, "0\n") == 0) printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   else printf(COLOR_RED "FAILED! IPv6 router advertisements are accepted.\n" COLOR_RESET);
}
