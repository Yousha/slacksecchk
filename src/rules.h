#ifndef RULES_H
#define RULES_H

#include <sys/types.h>

// CIS rules.
void check_file_permissions(const char *filename, mode_t expected_mode);
void check_log_files();
void check_password_policy();
void check_service(const char *service_name);
void check_disabled_service(const char *service_name);
void check_user_password_expiration();
void check_firewall_rules();
void check_auditd();
void check_access_control();
void check_logging();
void check_services();
void check_unnecessary_packages();
void check_umask_settings();
void check_core_dumps();
void check_ssh_config();
void check_world_writable_files();
void check_suid_sgid_files();
void check_empty_passwords();
void check_unused_kernel_modules();
void check_sensitive_commands();
void check_password_reuse_policy();
void check_cron_jobs();
void check_time_synchronization();
void check_selinux_apparmor();
void check_usb_storage();
void check_open_ports();
void check_bootloader_password();
void check_secure_mount_options();
void check_elilo_password();
// DISA STIG rules.
void check_core_dump_restriction();
void check_crypto_policy();
// NSA rules.
void check_ip_forwarding();
void check_packet_redirection();
void check_source_routed_packets();
void check_icmp_redirects();
void check_ipv6_router_advertisements();

// === Expanded Slackware-focused audits (v1.1.0.0) ===

// 1. Package & update surface
void check_slackpkg_installed();
void check_package_update_age();
void check_packages_dir_permissions();

// 2. rc.d service model
void check_rc_d_enabled_services();
void check_high_risk_rc_services();
void check_rc_script_permissions();
void check_rc_local_and_M();

// 3. Bootloader expansions
void check_lilo_password();
void check_grub_password_enhanced();
void check_bootloader_config_permissions();

// 4. Kernel & sysctl expansions
void check_kernel_hardening_sysctls();
void check_unwanted_kernel_modules();

// 5. Authentication & accounts
void check_securetty();
void check_login_defs();
void check_pam_password_quality();
void check_uid0_users();
void check_empty_or_locked_shell_accounts();
void check_shells_file();
void check_sudo_config();
void check_ssh_effective_config(void);

// 6. Filesystem & mounts
void check_fstab_secure_options();
void check_tmp_separation();
void check_proc_hidepid();
void check_unexpected_world_writable_dirs();

// 7. Network & listening services
void check_listening_services();
void check_tcp_wrappers();
void check_inetd_xinetd();

// 8. Logging & integrity
void check_syslog_remote();
void check_var_log_permissions();

// 9. Misc high-signal
void check_x11_nolisten();
void check_compiler_toolchains();
void check_issue_files();
void check_legacy_trust_files();

#endif // RULES_H
