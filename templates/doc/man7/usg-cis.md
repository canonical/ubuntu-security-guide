% USG-CIS(7) usg-benchmarks-<<USG_BENCHMARKS_ALTERNATIVE_PLACEHOLDER>> <<USG_BENCHMARKS_VERSION_PLACEHOLDER>>
% Eduardo Barretto <eduardo.barretto@canonical.com>
% <<DATE_PLACEHOLDER>>

# NAME
usg-cis - Information on CIS profiles implementation

# INTRODUCTION
As mentioned in the **usg-rules**(8) man page, five CIS profiles are available to be audited/applied: **cis_level1_server**, **cis_level2_server**, **cis_level1_workstation**, **cis_level2_workstation**, and **cis_level1_ec2**.

This man page provides additional information on all four and explain how to customize some variables in order to properly match the CIS requirements.

Last, this man page explains the limitations of the CIS profiles.

# PROFILES LEVELS AND TARGETS
This section provides basic explanation on levels and targets, For a through explanation, refer to the CIS benchmark document.

## Profiles Levels
The CIS benchmark and this implementation provides 2 levels of profiles: level 1 and level 2.
As stated in the CIS benchmark specification, level 2 rules "may negatively inhibit the utility or performance of the technology". On the
other hand, level 1 rules are generally safe to use.

That means level 1 profiles have smaller usability impact than their level 2 counterpart. However, level 2 are considered stricter, from the security standpoint, thus provide additional security.

However, there is one exception to this: rule 5.4.1.4 (Ensure inactive password lock is 30 days or less) applies to all login accounts, including the ones
with sudo permissions.

Hence, if there is a single account with sudo permissions and that account gets locked, this can lead to a situation where the administrator account is not
accessible, since, by default, the root user is locked in Ubuntu.

Also, note that level 2 profiles are an extension of level 1 profiles: **all rules applied on level 1 are also applied on level 2**.

## Profiles Targets
This is self-explanatory: server profiles are made for Canonical Ubuntu Server images, while Workstation profiles are made for Workstation images, which generally implies the use of a graphical interface. The ec2 profile is a variant of the server profile that largely serves to remove some rules that do not apply to an ec2 environment.

# CUSTOMIZING VARIABLES AFFECTING THE CIS PROFILES IMPLEMENTATIONS
Some rules can be fine-tuned by changing their variables.

For additional information on variables, check the **usg-variables**(7) man page.

See the **usg**(8) man page to get information on how to use tailoring files to change the value of variables.

## Selecting a time synchronization daemon

Use the XCCDF variable var\_timesync\_service to select which timesync daemon to install and configure.
Available options are:

- systemd-timesyncd (default)
- chronyd

## Selecting a firewall

Use the XCCDF variable var\_network\_filtering\_service to select which firewall to install and configure.
Available options are:

- nftables (default)
- iptables
- ufw

## Selecting a logging system

The selection of a single logging systems is not controled using an XCCDF variable as with time synchronization
and firewall.

Instead, correct rules are selected based on the status of the rsyslog service,
according to logic in CIS rule 6.1.1.4:

- if rsyslog service is active: rsyslog is configured (section 6.1.3) and section 6.1.2 is ignored
- if rsyslog service is inactive: systemd-journald is configured (section 6.1.2) and section 6.1.3 is ignored

## Apparmor mode

CIS rule 1.3.1.3 requires that all Apparmor profiles are either in **enforce** or **complain** mode.
Use the variable var\_apparmor\_mode to select one these values according to site requirements:

 - enforce: set all Apparmor profiles in /etc/apparmor.d to enforce mode
 - complain: set all Apparmor profiles in /etc/apparmor.d to complain mode
 - keep_existing_mode: (default) Do not change existing modes of Apparmor profiles. See note below.

**Important note:** On Ubuntu 24.04, changing the apparmor mode to enforce or complain on all profiles in /etc/apparmod.d can
break certain applications which use unconfined profiles. See https://workbench.cisecurity.org/benchmarks/18959/tickets/23987

## Some other interesting rules for customizing

### Rule 2.3.2.1 - var\_multiple\_time\_servers
This variable contains the list of time servers which the chosen time service will synchronize to.

The value must be a comma-separated list of servers. The default values are the safe ones used by Canonical on Ubuntu.

### Rule 5.3.3.2.3 - var\_password\_pam\_minclass, var\_password\_pam\_dcredit, var\_password\_pam\_ucredit, var\_password\_pam\_ocredit, var\_password\_pam\_lcredit
These variables are used to set the password creation parameters of the pam\_pwquality module. The names of the variables reflect those parameters.

Default values are according to the CIS benchmark.

Check the pam\_pwquality module man page for more information on the parameters.

# RULES LIMITATIONS

## Manual rules

Rules listed in this section must be assessed manually according to
instructions in the CIS Benchmark (see *INTERNET RESOURCES*).

USG does not include an automated audit or remediation for these rules.

- 1.1.1.10   Ensure unused filesystems kernel modules are not available
- 1.2.1.1	   Ensure GPG keys are configured
- 1.2.1.2	   Ensure package manager repositories are configured
- 1.2.2.1	   Ensure updates, patches, and additional security software are installed
- 2.1.22	   Ensure only approved services are listening on a network interface
- 3.1.1	   Ensure IPv6 status is identified
- 4.2.5	   Ensure ufw outbound connections are configured
- 4.3.3	   Ensure iptables are flushed with nftables
- 4.3.7	   Ensure nftables outbound and established connections are configured
- 4.4.2.3	   Ensure iptables outbound and established connections are configured
- 4.4.3.3	   Ensure ip6tables outbound and established connections are configured
- 5.3.3.2.3  Ensure password complexity is configured
- 5.4.1.2	   Ensure minimum password days is configured
- 6.1.1.2	   Ensure journald log file access is configured
- 6.1.1.3	   Ensure journald log file rotation is configured
- 6.1.2.1.2  Ensure systemd-journal-upload authentication is configured
- 6.1.3.5	   Ensure rsyslog logging is configured
- 6.1.3.6	   Ensure rsyslog is configured to send logs to a remote log host
- 6.1.3.8	   Ensure logrotate is configured
- 6.2.3.21   Ensure the running and on disk configuration is the same
- 7.1.13	   Ensure SUID and SGID files are reviewed

## Rules with no remediation

Rules listed in this section do not come with an automated remediation as it is
either dependent on local site policy, or is considered too disruptive, possibly leading to system lockout.
The remediations must be performed manually according to the instructions in the
CIS benchmark (see *INTERNET RESOURCES*).


- 1.1.2.3.1 	 Ensure separate partition exists for /home 	 (usg rules: partition_for_home)
- 1.1.2.4.1 	 Ensure separate partition exists for /var 	 (usg rules: partition_for_var)
- 1.1.2.5.1 	 Ensure separate partition exists for /var/tmp 	 (usg rules: partition_for_var_tmp)
- 1.1.2.6.1 	 Ensure separate partition exists for /var/log 	 (usg rules: partition_for_var_log)
- 1.1.2.7.1 	 Ensure separate partition exists for /var/log/audit 	 (usg rules: partition_for_var_log_audit)
- 1.4.1 	 Ensure bootloader password is set 	 (usg rules: grub2_uefi_password)
- 2.1.21 	 Ensure mail transfer agent is configured for local-only mode 	 (usg rules: has_nonlocal_mta)
- 4.2.3 	 Ensure ufw service is enabled 	 (usg rules: check_ufw_active)
- 4.2.6 	 Ensure ufw firewall rules exist for all open ports 	 (usg rules: ufw_rules_for_open_ports)
- 4.2.7 	 Ensure ufw default deny firewall policy 	 (usg rules: set_ufw_default_rule)
- 4.4.2.4 	 Ensure iptables firewall rules exist for all open ports 	 (usg rules: iptables_rules_for_open_ports)
- 4.4.3.4 	 Ensure ip6tables firewall rules exist for all open ports 	 (usg rules: ip6tables_rules_for_open_ports)
- 5.1.4 	 Ensure sshd access is configured 	 (usg rules: sshd_limit_user_access)
- 5.4.1.6 	 Ensure all users last password change date is in the past 	 (usg rules: accounts_password_last_change_is_in_past)
- 5.4.2.2 	 Ensure root is the only GID 0 account 	 (usg rules: accounts_root_gid_zero)
- 5.4.2.4 	 Ensure root account access is controlled 	 (usg rules: ensure_root_access_controlled)
- 5.4.2.5 	 Ensure root path integrity 	 (usg rules: root_path_all_dirs,no_dirs_unowned_by_root,root_path_no_dot,accounts_root_path_dirs_no_write)
- 5.4.2.8 	 Ensure accounts without a valid login shell are locked 	 (usg rules: no_invalid_shell_accounts_unlocked)
- 7.1.12 	 Ensure no files or directories without an owner and a group exist 	 (usg rules: no_files_unowned_by_user,file_permissions_ungroupowned)
- 7.2.1 	 Ensure accounts in /etc/passwd use shadowed passwords 	 (usg rules: accounts_password_all_shadowed)
- 7.2.3 	 Ensure all groups in /etc/passwd exist in /etc/group 	 (usg rules: gid_passwd_group_same)
- 7.2.6 	 Ensure no duplicate GIDs exist 	 (usg rules: group_unique_id)
- 7.2.7 	 Ensure no duplicate user names exist 	 (usg rules: account_unique_name)
- 7.2.8 	 Ensure no duplicate group names exist 	 (usg rules: group_unique_name)
- 7.2.10 	 Ensure local interactive user dot files access is configured 	 (usg rules: no_forward_files,no_netrc_files)


# INTERNET RESOURCES
Ubuntu 24.04 CIS Benchmark v1.0.0: https://workbench.cisecurity.org/benchmarks/18959

# SEE ALSO
**usg**(8), **usg-rules**(7), **usg-variables**(7)

# COPYRIGHT
Copyright <<YEAR_PLACEHOLDER>> Canonical Limited. All rights reserved.

The implementation of CIS rules, profiles, scripts, and other assets are based on the ComplianceAsCode open source project (https://www.open-scap.org/security-policies/scap-security-guide).

ComplianceAsCode's license file can be found in the /usr/share/ubuntu-scap-security-guides/benchmarks directory.
