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

#endif // RULES_H
