#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "rules.h"

// ANSI color codes for terminal output.
#define COLOR_GREEN "\033[1;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

/**
 * @brief CIS: Checks file permissions of important files.
 *
 * @param filename The path to file to check.
 * @param expected_mode The expected permissions (octal).
 */
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

/**
 * @brief CIS: Checks if log files exist and have proper permissions.
 */
void check_log_files() {
   // Slackware defaults
   check_file_permissions("/var/log/messages", 0600);
   check_file_permissions("/var/log/secure", 0600);
   check_file_permissions("/var/log/maillog", 0600);
   check_file_permissions("/var/log/syslog", 0644);
   check_file_permissions("/var/log/messages", 0644);
}

/**
 * @brief CIS: Verifies that password policy is enforced.
 */
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

/**
 * @brief CIS: Checks if a service is running (Slackware version).
 *
 * @param service_name The name of service to check.
 */
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

/**
 * @brief CIS: Check an unnecessary service is disabled (Slackware version).
 *
 * @param service_name The name of service to check.
 */
void check_disabled_service(const char *service_name) {
   printf("\n[CIS] Checking if unnecessary service '%s' is disabled... ", service_name);
   char script_path[256];
   snprintf(script_path, sizeof(script_path), "/etc/rc.d/rc.%s", service_name);

   // Check if service script exists and is executable.
   if (access(script_path, X_OK) == 0) {
      printf(COLOR_RED "FAILED! Unnecessary service '%s' is enabled.\n" COLOR_RESET, service_name);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Verifies that user accounts have password expiration policies.
 */
void check_user_password_expiration() {
   printf("\n[CIS] Checking password expiration for user accounts... ");
   system("chage -l root | grep -E 'Password expires|Account expires' || echo '" COLOR_RED "FAILED! Could not verify password expiration for root." COLOR_RESET "'");
}

/**
 * @brief CIS: Verifies firewall rules are configured.
 */
void check_firewall_rules() {
   printf("\n[CIS] Checking firewall is configured... ");

   if (system("iptables -L > /dev/null 2>&1") != 0) {
      printf(COLOR_RED "FAILED! iptables not configured or inactive.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Checks if audit daemon (auditd) is running (SysV Init version).
 */
void check_auditd() {
   printf("\n[CIS] Checking audit logging... ");

   if (system("service auditd status > /dev/null 2>&1") != 0) {
      printf(COLOR_RED "FAILED! auditd is not running.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Verifies access control settings for sensitive directories.
 */
void check_access_control() {
   check_file_permissions("/etc", 0755);
   check_file_permissions("/root", 0700);
   check_file_permissions("/home", 0755);
}

/**
 * @brief CIS: Verifies logging configurations (SysV Init version).
 */
void check_logging() {
   printf("\n[CIS] Checking logging configurations... ");

   // Check rsyslog or syslog-ng is running.
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

/**
 * @brief CIS: Check unnecessary services are disabled.
 */
void check_services() {
   check_disabled_service("rpcbind");
   check_disabled_service("avahi-daemon");
   check_disabled_service("cups");
}

/**
 * @brief CIS: Check for unnecessary packages using Slackware's package management system.
 */
void check_unnecessary_packages() {
   const char *packages[] = {"nmap", "telnet", "vsftpd"};
   int failed = 0;

   for (int i = 0; i < (int)(sizeof(packages) / sizeof(packages[0])); i++) {
   	printf("\n[CIS] Checking for unnecessary package '%s'... ", packages[i]);
      const char *package_name = packages[i];
      // Use `ls` to check if package exists in /var/log/packages.
      char command[256];
      snprintf(command, sizeof(command), "ls /var/log/packages | grep '^%s-' > /dev/null 2>&1", package_name);
      if (system(command) == 0) {
         printf(COLOR_RED "FAILED! Unnecessary package '%s' is installed.\n" COLOR_RESET, package_name);
         failed = 1;
      }
   }

   if (!failed) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Verify umask settings.
 */
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

/**
 * @brief CIS: Disable core dumps.
 */
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

/**
 * @brief CIS: Check SSH configuration.
 */
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
      if (strstr(line, "PermitRootLogin no")) {
         root_login_disabled = 1;
      }
      if (strstr(line, "Protocol 2")) {
         protocol_2_enabled = 1;
      }
   }

   fclose(file);

   if (root_login_disabled && protocol_2_enabled) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! SSH is not configured securely.\n" COLOR_RESET);
      if (!root_login_disabled) {
         printf(COLOR_RED "FAILED! PermitRootLogin is not set to 'no'.\n" COLOR_RESET);
      }
      if (!protocol_2_enabled) {
         printf(COLOR_RED "FAILED! Protocol is not set to '2'.\n" COLOR_RESET);
      }
   }
}

/**
 * @brief CIS: Check for world-writable files.
 */
void check_world_writable_files() {
   printf("\n[CIS] Checking for world-writable files... ");
   char command[512];
   snprintf(command, sizeof(command), "find / -xdev -type f -perm -0002 -print > /dev/null 2>&1");

   if (system(command) == 0) {
      printf(COLOR_RED "FAILED! World-writable files found on system.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Check for SUID/SGID files.
 */
void check_suid_sgid_files() {
   printf("\n[CIS] Checking for SUID/SGID files... ");
   char command[512];
   snprintf(command, sizeof(command), "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -print > /dev/null 2>&1");

   if (system(command) == 0) {
      printf(COLOR_RED "FAILED! SUID/SGID files found on system.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Check for empty passwords.
 */
void check_empty_passwords() {
   printf("\n[CIS] Checking for empty passwords... ");

   // Properly escape backslash in '\+' to avoid warning.
   if (system("grep '^\\+:' /etc/passwd > /dev/null 2>&1") == 0) {
      printf(COLOR_RED "FAILED! Accounts with empty passwords found.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Disable unused kernel modules for servers.
 */
void check_unused_kernel_modules() {
   printf("\n[CIS] Checking for unused kernel modules for servers... ");
   // Example: Check for unused USB modules.
   char command[256];
   snprintf(command, sizeof(command), "lsmod | grep -E 'usb_storage|firewire_core' > /dev/null 2>&1");

   if (system(command) == 0) {
      printf(COLOR_RED "FAILED! Unused kernel modules (usb_storage, firewire_core) are loaded.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Restrict access to sensitive commands (sudo).
 */
void check_sensitive_commands() {
   printf("\n[CIS] Checking access to sensitive commands... ");

   if (access("/etc/sudoers", F_OK) != 0) {
      printf(COLOR_YELLOW "Notice: /etc/sudoers file not found.\n" COLOR_RESET);
      return;
   }

   char command[256];
   snprintf(command, sizeof(command), "grep '^%%wheel' /etc/sudoers > /dev/null 2>&1");

   if (system(command) != 0) {
      printf(COLOR_RED "FAILED! Sensitive commands (sudo) are not properly restricted.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Enforce password reuse policies.
 */
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

/**
 * @brief CIS: Check for unnecessary CRON jobs.
 */
void check_cron_jobs() {
   printf("\n[CIS] Checking for unnecessary CRON jobs... ");
   char command[256];
   snprintf(command, sizeof(command), "find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly -type f -exec grep -v '^#' {} \\; > /dev/null 2>&1");

   if (system(command) == 0) {
      printf(COLOR_RED "FAILED! Unnecessary CRON jobs found.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Verify system time synchronization.
 */
void check_time_synchronization() {
   printf("\n[CIS] Checking system time synchronization... ");

   if (system("service ntp status > /dev/null 2>&1") != 0 && system("service chronyd status > /dev/null 2>&1") != 0) {
      printf(COLOR_RED "FAILED! System time synchronization (NTP/Chrony) is not running.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Enable SELinux/AppArmor.
 */
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

/**
 * @brief CIS: Disable USB storage devices.
 */
void check_usb_storage() {
   printf("\n[CIS] Checking USB storage devices... ");
   char command[256];
   snprintf(command, sizeof(command), "modprobe -n -v usb-storage | grep 'install /bin/true' > /dev/null 2>&1");

   if (system(command) != 0) {
      printf(COLOR_RED "FAILED! USB storage devices are not disabled.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Check for open ports and listening services.
 */
void check_open_ports() {
   printf("\n[CIS] Checking for open ports... ");
   char command[256];
   snprintf(command, sizeof(command), "netstat -tuln | grep -E '0.0.0.0:|:::' > /dev/null 2>&1");

   if (system(command) == 0) {
      printf(COLOR_RED "FAILED! Open ports found. Investigate unnecessary services.\n" COLOR_RESET);
   } else {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Verify secure GRUB bootloader configuration.
 */
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

/**
 * @brief CIS: Enforce secure mount options.
 */
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
      if (strstr(line, "noexec")) {
         noexec_found = 1;
      }
      if (strstr(line, "nosuid")) {
         nosuid_found = 1;
      }
   }

   fclose(file);

   if (noexec_found && nosuid_found) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! Secure mount options (noexec, nosuid) are not fully configured.\n" COLOR_RESET);
   }
}

/**
 * @brief CIS: Check if ELiLo bootloader exists and has a password set.
 */
 void check_elilo_password() {
   printf("\n[CIS]: Checking if ELiLo bootloader has a password set... ");

   // Check if ELiLo is installed.
   if (access("/boot/efi/EFI/elilo.efi", F_OK) != 0) {
      printf(COLOR_GREEN "PASSED! ELiLo bootloader not found.\n" COLOR_RESET);
      return;
   }

   // Check if elilo.conf file exists.
   const char *elilo_conf_path = "/etc/elilo.conf";
   FILE *file = fopen(elilo_conf_path, "r");

   if (file == NULL) {
      printf(COLOR_RED "FAILED! ELiLo bootloader is installed but config is missing.\n" COLOR_RESET);
      return;
   }

   // Check for a password entry in elilo.conf file.
   char line[256];
   int password_found = 0;

   while (fgets(line, sizeof(line), file)) {
      if (strstr(line, "password")) {
         password_found = 1;
         break;
      }
   }

   fclose(file);

   if (password_found) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! ELiLo bootloader does not have a password set.\n" COLOR_RESET);
   }
}

/**
 * @brief DISA STIG: Check core dumps are restricted.
 */
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
      if (strstr(line, "* hard core 0")) {
         core_dump_disabled = 1;
         break;
      }
   }

   fclose(file);

   if (core_dump_disabled) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! Core dumps are not restricted in /etc/security/limits.conf.\n" COLOR_RESET);
   }
}

/**
 * @brief DISA STIG: Check system-wide crypto policy is enabled.
 */
void check_crypto_policy() {
   printf("\n[DISA STIG] Checking system-wide crypto policy enabled... ");
   FILE *file = fopen("/etc/crypto-policies/config", "r");

   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /etc/crypto-policies/config.\n" COLOR_RESET);
      return;
   }

   char line[256];
   int crypto_policy_found = 0;

   while (fgets(line, sizeof(line), file)) {
      if (strstr(line, "DEFAULT") || strstr(line, "FUTURE")) {
         crypto_policy_found = 1;
         break;
      }
   }

   fclose(file);

   if (crypto_policy_found) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! System-wide crypto policy is not enabled.\n" COLOR_RESET);
   }
}

/**
 * @brief NSA: Check IP forwarding is disabled (IPv4 Forwarding).
 */
void check_ip_forwarding() {
   printf("\n[NSA] Checking if IP forwarding is disabled... ");
   FILE *file = fopen("/proc/sys/net/ipv4/ip_forward", "r");

   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /proc/sys/net/ipv4/ip_forward.\n" COLOR_RESET);
      return;
   }

   char value[16];
   fgets(value, sizeof(value), file);
   fclose(file);

   if (strcmp(value, "0\n") == 0) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! IP forwarding is enabled.\n" COLOR_RESET);
   }
}

/**
 * @brief NSA: Check packet redirection is disabled (Send Packet Redirects).
 */
void check_packet_redirection() {
   printf("\n[NSA] Checking if packet redirection is disabled... ");
   FILE *file = fopen("/proc/sys/net/ipv4/conf/all/send_redirects", "r");

   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /proc/sys/net/ipv4/conf/all/send_redirects.\n" COLOR_RESET);
      return;
   }

   char value[16];
   fgets(value, sizeof(value), file);
   fclose(file);

   if (strcmp(value, "0\n") == 0) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! Packet redirection is enabled.\n" COLOR_RESET);
   }
}

/**
 * @brief NSA: Check source routed packets are not accepted (Source Routed Packets).
 */
void check_source_routed_packets() {
   printf("\n[NSA] Checking if source routed packets are not accepted... ");
   FILE *file = fopen("/proc/sys/net/ipv4/conf/all/accept_source_route", "r");

   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /proc/sys/net/ipv4/conf/all/accept_source_route.\n" COLOR_RESET);
      return;
   }

   char value[16];
   fgets(value, sizeof(value), file);
   fclose(file);

   if (strcmp(value, "0\n") == 0) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! Source routed packets are accepted.\n" COLOR_RESET);
   }
}

/**
 * @brief NSA: Check ICMP redirects are not accepted (ICMP Redirect Acceptance).
 */
void check_icmp_redirects() {
   printf("\n[NSA] Checking if ICMP redirects are not accepted... ");
   FILE *file = fopen("/proc/sys/net/ipv4/conf/all/accept_redirects", "r");

   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /proc/sys/net/ipv4/conf/all/accept_redirects.\n" COLOR_RESET);
      return;
   }

   char value[16];
   fgets(value, sizeof(value), file);
   fclose(file);

   if (strcmp(value, "0\n") == 0) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! ICMP redirects are accepted.\n" COLOR_RESET);
   }
}

/**
 * @brief NSA: Check IPv6 router advertisements are not accepted (IPv6 Router Advertisements).
 */
void check_ipv6_router_advertisements() {
   printf("\n[NSA] Checking if IPv6 router advertisements are not accepted... ");
   FILE *file = fopen("/proc/sys/net/ipv6/conf/all/accept_ra", "r");

   if (file == NULL) {
      printf(COLOR_YELLOW "Error: Unable to access /proc/sys/net/ipv6/conf/all/accept_ra.\n" COLOR_RESET);
      return;
   }

   char value[16];
   fgets(value, sizeof(value), file);
   fclose(file);

   if (strcmp(value, "0\n") == 0) {
      printf(COLOR_GREEN "PASSED!\n" COLOR_RESET);
   } else {
      printf(COLOR_RED "FAILED! IPv6 router advertisements are accepted.\n" COLOR_RESET);
   }
}
