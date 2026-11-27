/**
 * Name: SlackSecChk
 * Description: A C tool to audit Slackware Linux(>=14) security against CIS, NSA, and DISA benchmarks
 * Version: 1.1.0.0
 * Locale: en_International
 * Last update: 2026
 * Architecture: 64bit
 * API: libc 2.31
 * Compiler: GCC 10.1.*
 * Builder: CMake 3.18.*
 * License: GPL-3.0
 * Copyright: Copyright 2025-2026 Yousha Aleayoub.
 * Producer: Yousha Aleayoub
 * Maintainer: Yousha Aleayoub
 * Contact: yousha.a@hotmail.com
 * Link: http://yousha.blog.ir
 */

#include <stdio.h>
#include <string.h>
#include "rules.h"
#include "audit_utils.h"
#define printf audit_printf

#define SLACKSECCHK_VERSION "1.1.0.0"

static void print_usage(FILE *stream) {
   fprintf(stream,
      "Usage: slacksecchk [OPTIONS]\n"
      "Run the configured Slackware security audit.\n\n"
      "Options:\n"
      "  -h, --help           Show this help and exit.\n"
      "  -V, --version        Show version information and exit.\n"
      "      --color=MODE     Color mode: auto, always, or never.\n"
      "      --no-color       Disable colored output.\n"
      "      --format=text    Human-readable output (default).\n"
      "      --format=json    Emit a machine-readable JSON summary.\n");
}

/**
 * @brief Entry point for slacksecchk program.
 *
 * @return 0 when the audit completes, 2 for invalid command-line arguments.
 */
int main(int argc, char *argv[]) {
   int show_help = 0;
   int show_version = 0;
   int color_mode = AUDIT_COLOR_AUTO;
   int json_output = 0;

   for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
         show_help = 1;
      } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
         show_version = 1;
      } else if (strcmp(argv[i], "--no-color") == 0 || strcmp(argv[i], "--color=never") == 0) {
         color_mode = AUDIT_COLOR_NEVER;
      } else if (strcmp(argv[i], "--color=always") == 0) {
         color_mode = AUDIT_COLOR_ALWAYS;
      } else if (strcmp(argv[i], "--color=auto") == 0) {
         color_mode = AUDIT_COLOR_AUTO;
      } else if (strcmp(argv[i], "--format=json") == 0) {
         json_output = 1;
      } else if (strcmp(argv[i], "--format=text") == 0) {
         json_output = 0;
      } else {
         fprintf(stderr, "slacksecchk: unknown option: %s\n", argv[i]);
         print_usage(stderr);
         return 2;
      }
   }

   if (show_help) {
      print_usage(stdout);
      return 0;
   }
   if (show_version) {
      printf("slacksecchk %s\n", SLACKSECCHK_VERSION);
      return 0;
   }
   audit_reset_summary();
   audit_set_json_output(json_output);
   audit_set_color_mode(color_mode);
   printf("\n");
   printf("slacksecchk %s\n", SLACKSECCHK_VERSION);
   printf("slacksecchk: Auditing system security...\n");

   /* Classic CIS-style checks */
   audit_set_current_rule("SSC-FILE-PERMISSIONS-PASSWD", "filesystem");
   check_file_permissions("/etc/passwd", 0644);
   audit_set_current_rule("SSC-FILE-PERMISSIONS-SHADOW", "filesystem");
   check_file_permissions("/etc/shadow", 0600);
   audit_set_current_rule("SSC-LOG-FILES", "filesystem");
   check_log_files();
   audit_set_current_rule("SSC-PASSWORD-POLICY", "accounts");
   check_password_policy();
   audit_set_current_rule("SSC-SERVICE", "services");
   check_service("ssh");
   audit_set_current_rule("SSC-SERVICE", "services");
   check_service("firewalld");
   audit_set_current_rule("SSC-DISABLED-SERVICE", "services");
   check_disabled_service("telnet");
   audit_set_current_rule("SSC-DISABLED-SERVICE", "services");
   check_disabled_service("vsftpd");
   audit_set_current_rule("SSC-USER-PASSWORD-EXPIRATION", "accounts");
   check_user_password_expiration();
   audit_set_current_rule("SSC-FIREWALL-RULES", "network");
   check_firewall_rules();
   audit_set_current_rule("SSC-AUDITD", "logging");
   check_auditd();
   audit_set_current_rule("SSC-ACCESS-CONTROL", "general");
   check_access_control();
   audit_set_current_rule("SSC-LOGGING", "logging");
   check_logging();
   audit_set_current_rule("SSC-SERVICES", "services");
   check_services();
   audit_set_current_rule("SSC-UNNECESSARY-PACKAGES", "packages");
   check_unnecessary_packages();
   audit_set_current_rule("SSC-UMASK-SETTINGS", "system");
   check_umask_settings();
   audit_set_current_rule("SSC-CORE-DUMPS", "system");
   check_core_dumps();
   audit_set_current_rule("SSC-SSH-CONFIG", "accounts");
   check_ssh_config();
   audit_set_current_rule("SSC-WORLD-WRITABLE-FILES", "filesystem");
   check_world_writable_files();
   audit_set_current_rule("SSC-SUID-SGID-FILES", "filesystem");
   check_suid_sgid_files();
   audit_set_current_rule("SSC-EMPTY-PASSWORDS", "accounts");
   check_empty_passwords();
   audit_set_current_rule("SSC-UNUSED-KERNEL-MODULES", "kernel");
   check_unused_kernel_modules();
   audit_set_current_rule("SSC-SENSITIVE-COMMANDS", "system");
   check_sensitive_commands();
   audit_set_current_rule("SSC-PASSWORD-REUSE-POLICY", "accounts");
   check_password_reuse_policy();
   audit_set_current_rule("SSC-CRON-JOBS", "system");
   check_cron_jobs();
   audit_set_current_rule("SSC-TIME-SYNCHRONIZATION", "system");
   check_time_synchronization();
   audit_set_current_rule("SSC-SELINUX-APPARMOR", "system");
   check_selinux_apparmor();
   audit_set_current_rule("SSC-USB-STORAGE", "system");
   check_usb_storage();
   audit_set_current_rule("SSC-OPEN-PORTS", "network");
   check_open_ports();
   audit_set_current_rule("SSC-BOOTLOADER-PASSWORD", "boot");
   check_bootloader_password();
   audit_set_current_rule("SSC-SECURE-MOUNT-OPTIONS", "filesystem");
   check_secure_mount_options();
   audit_set_current_rule("SSC-ELILO-PASSWORD", "boot");
   check_elilo_password();
   /* DISA STIG checks */
   audit_set_current_rule("SSC-CORE-DUMP-RESTRICTION", "system");
   check_core_dump_restriction();
   audit_set_current_rule("SSC-CRYPTO-POLICY", "system");
   check_crypto_policy();
   /* NSA Hardening Guide checks */
   audit_set_current_rule("SSC-IP-FORWARDING", "kernel");
   check_ip_forwarding();
   audit_set_current_rule("SSC-PACKET-REDIRECTION", "kernel");
   check_packet_redirection();
   audit_set_current_rule("SSC-SOURCE-ROUTED-PACKETS", "kernel");
   check_source_routed_packets();
   audit_set_current_rule("SSC-ICMP-REDIRECTS", "kernel");
   check_icmp_redirects();
   audit_set_current_rule("SSC-IPV6-ROUTER-ADVERTISEMENTS", "kernel");
   check_ipv6_router_advertisements();
   /* === Expanded Slackware-focused audits (v1.1.0.0) === */

   /* 1. Package & update surface */
   audit_set_current_rule("SSC-SLACKPKG-INSTALLED", "general");
   check_slackpkg_installed();
   audit_set_current_rule("SSC-PACKAGE-UPDATE-AGE", "packages");
   check_package_update_age();
   audit_set_current_rule("SSC-PACKAGES-DIR-PERMISSIONS", "packages");
   check_packages_dir_permissions();
   /* 2. rc.d service model */
   audit_set_current_rule("SSC-RC-D-ENABLED-SERVICES", "services");
   check_rc_d_enabled_services();
   audit_set_current_rule("SSC-HIGH-RISK-RC-SERVICES", "services");
   check_high_risk_rc_services();
   audit_set_current_rule("SSC-RC-SCRIPT-PERMISSIONS", "services");
   check_rc_script_permissions();
   audit_set_current_rule("SSC-RC-LOCAL-AND-M", "services");
   check_rc_local_and_M();
   /* 3. Bootloader expansions */
   audit_set_current_rule("SSC-LILO-PASSWORD", "boot");
   check_lilo_password();
   audit_set_current_rule("SSC-GRUB-PASSWORD-ENHANCED", "boot");
   check_grub_password_enhanced();
   audit_set_current_rule("SSC-BOOTLOADER-CONFIG-PERMISSIONS", "boot");
   check_bootloader_config_permissions();
   /* 4. Kernel & sysctl expansions */
   audit_set_current_rule("SSC-KERNEL-HARDENING-SYSCTLS", "kernel");
   check_kernel_hardening_sysctls();
   audit_set_current_rule("SSC-UNWANTED-KERNEL-MODULES", "kernel");
   check_unwanted_kernel_modules();
   /* 5. Authentication & accounts */
   audit_set_current_rule("SSC-SECURETTY", "accounts");
   check_securetty();
   audit_set_current_rule("SSC-LOGIN-DEFS", "accounts");
   check_login_defs();
   audit_set_current_rule("SSC-PAM-PASSWORD-QUALITY", "accounts");
   check_pam_password_quality();
   audit_set_current_rule("SSC-UID0-USERS", "accounts");
   check_uid0_users();
   audit_set_current_rule("SSC-EMPTY-OR-LOCKED-SHELL-ACCOUNTS", "accounts");
   check_empty_or_locked_shell_accounts();
   audit_set_current_rule("SSC-SHELLS-FILE", "accounts");
   check_shells_file();
   audit_set_current_rule("SSC-SUDO-CONFIG", "accounts");
   check_sudo_config();
   audit_set_current_rule("SSC-SSH-EFFECTIVE-CONFIG", "accounts");
   check_ssh_effective_config();
   /* 6. Filesystem & mounts */
   audit_set_current_rule("SSC-FSTAB-SECURE-OPTIONS", "filesystem");
   check_fstab_secure_options();
   audit_set_current_rule("SSC-TMP-SEPARATION", "filesystem");
   check_tmp_separation();
   audit_set_current_rule("SSC-PROC-HIDEPID", "filesystem");
   check_proc_hidepid();
   audit_set_current_rule("SSC-UNEXPECTED-WORLD-WRITABLE-DIRS", "filesystem");
   check_unexpected_world_writable_dirs();
   /* 7. Network & listening services */
   audit_set_current_rule("SSC-LISTENING-SERVICES", "services");
   check_listening_services();
   audit_set_current_rule("SSC-TCP-WRAPPERS", "network");
   check_tcp_wrappers();
   audit_set_current_rule("SSC-INETD-XINETD", "services");
   check_inetd_xinetd();
   /* 8. Logging & integrity */
   audit_set_current_rule("SSC-SYSLOG-REMOTE", "logging");
   check_syslog_remote();
   audit_set_current_rule("SSC-VAR-LOG-PERMISSIONS", "logging");
   check_var_log_permissions();
   /* 9. Misc high-signal */
   audit_set_current_rule("SSC-X11-NOLISTEN", "general");
   check_x11_nolisten();
   audit_set_current_rule("SSC-COMPILER-TOOLCHAINS", "system");
   check_compiler_toolchains();
   audit_set_current_rule("SSC-ISSUE-FILES", "system");
   check_issue_files();
   audit_set_current_rule("SSC-LEGACY-TRUST-FILES", "system");
   check_legacy_trust_files();
   if (json_output) {
      if (audit_write_json_summary(stdout, SLACKSECCHK_VERSION) != 0)
         return 2;
      return audit_summary_exit_code();
   }

   printf("\n");
   printf("slacksecchk: Audit has finished.\n");
   printf("\n");
   return 0;
}
