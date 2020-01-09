/**
 * Name: SlackSecChk
 * Description: A C tool to audit Slackware Linux(>=14) security against CIS, NSA, and DISA benchmarks
 * Version: 1.0.0.1
 * Locale: en_International
 * Last update: 2020
 * Architecture: 64bit
 * API: libc 2.31
 * Compiler: GCC 10.1.*
 * Builder: CMake 3.18.*
 * License: GPL-3.0
 * Copyright: Copyright (c) 2020 Yousha Aleayoub.
 * Producer: Yousha Aleayoub
 * Maintainer: Yousha Aleayoub
 * Contact: yousha.a@hotmail.com
 * Link: http://yousha.blog.ir
 */

#include <stdio.h>
#include "rules.h"

/**
 * @brief Entry point for slacksecchk program.
 *
 * @return int Returns 0 If successful execution of all audits.
 */
int main() {
   printf("\n");
   printf("slacksecchk 1.0.0.1\n");
   printf("slacksecchk: Auditing system security...\n");
   check_file_permissions("/etc/passwd", 0644);
   check_file_permissions("/etc/shadow", 0600);
   check_log_files();
   check_password_policy();
   check_service("ssh");
   check_service("firewalld");
   check_disabled_service("telnet");
   check_disabled_service("vsftpd");
   check_user_password_expiration();
   check_firewall_rules();
   check_auditd();
   check_access_control();
   check_logging();
   check_services();
   check_unnecessary_packages();
   check_umask_settings();
   check_core_dumps();
   check_ssh_config();
   check_world_writable_files();
   check_suid_sgid_files();
   check_empty_passwords();
   check_unused_kernel_modules();
   check_sensitive_commands();
   check_password_reuse_policy();
   check_cron_jobs();
   check_time_synchronization();
   check_selinux_apparmor();
   check_usb_storage();
   check_open_ports();
   check_bootloader_password();
   check_secure_mount_options();
   check_elilo_password();
   // DISA STIG checks.
   check_core_dump_restriction();
   check_crypto_policy();
   // NSA Hardening Guide checks
   check_ip_forwarding();
   check_packet_redirection();
   check_source_routed_packets();
   check_icmp_redirects();
   check_ipv6_router_advertisements();
   printf("\n");
   printf("slacksecchk: Audit has finished.\n");
   printf("\n");
   return 0;
}
