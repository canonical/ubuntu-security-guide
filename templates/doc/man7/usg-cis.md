% USG-CIS(7) usg-benchmarks-<<USG_BENCHMARKS_ALTERNATIVE_PLACEHOLDER>> <<USG_BENCHMARKS_VERSION_PLACEHOLDER>>
% Eduardo Barretto <eduardo.barretto@canonical.com>
% <<DATE_PLACEHOLDER>>

# NAME
usg-cis - Information on CIS profiles implementation

# INTRODUCTION
As mentioned in the **usg-rules**(8) man page, five CIS profiles are available to be audited/applied: **cis_level1_server**, **cis_level2_server**, **cis_level1_workstation**, and **cis_level2_workstation**.

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
This is self-explanatory: server profiles are made for Canonical Ubuntu Server images, while Workstation profiles are made for Workstation images, which generally implies the use of a graphical interface. 

# CUSTOMIZING VARIABLES AFFECTING THE CIS PROFILES IMPLEMENTATIONS
Some rules can be fine-tuned by changing their variables. However, CIS benchmarks provides some variables with phony parameters which **must be customized** so the hardening scripts can be properly applied and the audit can properly check them.

For additional information on variables, check the **usg-variables**(7) man page.

See the **usg**(8) man page to get information on how to use tailoring files to change the value of variables.

## Rules that must be customized
The list of variables below contains a brief explanation of the variables which *must be customized* and what rules they are related to.

### Rule 1.5.1 - var\_grub2\_user, var\_grub2\_passwd\_hash
Above variables are used to set the Grub2 user and password hash. Rule 1.5.1 uses that information to prevent changes to the grub2 entries during the bootloader execution.

If the var\_grub2\_passwd\_hash value is left with the default value '\*', then no password will be set to the bootloader.

To generate the hash value, use the command `grub_mkpasswd_pbkdf2`

### Rule 1.5.3 - var\_root\_passwd\_hash
This variable holds the hash which will be set into the /etc/shadow entry for the root user. In order to create this hash, use the command below:

`# openssl passwd -6`

and type the password. Copy the generated hash to the value of the aforementioned variable.

If that variable is left with the default value, the **usg** tool **will not set the root password** and the audit will fail if there is not a root password available.

### Rule 5.2.17 - var\_sshd\_allow\_users\_valid, var\_sshd\_allow\_groups\_valid, var\_sshd\_deny\_users\_valid, var\_sshd\_deny\_groups\_valid
These variables are used to set the ssh server parameters AllowUsers, AllowGroups, DenyUsers, DenyGroups, respectively, which allows an administrator to restrict user/group access to ssh remote access.

The value must be a comma-separated list of users (or groups). If the variables are left with the default value, the **usg** too **will not include those parameters in the ssh server config file**, to avoid lockups.

Check the ssh server man page to get more information on the parameters.

## Some other interesting rules for customizing

### Rule 2.2.1.3 - var\_multiple\_time\_servers
This variable contains the list of time servers which the chosen time service will synchronize to.

The value must be a comma-separated list of servers. The default values are the safe ones used by Canonical on Ubuntu.

### Rule 5.3.1 - var\_password\_pam\_minlen, var\_password\_pam\_minclass, var\_password\_pam\_dcredit, var\_password\_pam\_ucredit, var\_password\_pam\_ocredit, var\_password\_pam\_lcredit, var\_password\_pam\_retry
These variables are used to set the password creation parameters of the pam\_pwquality module. The names of the variables reflect those parameters.

Default values are according to the CIS benchmark.

Check the pam\_pwquality module man page for more information on the parameters.

# RULES LIMITATIONS
## Rule 1.1.10 - partition\_for\_var
## Rule 1.1.11 - partition\_for\_var\_tmp
## Rule 1.1.15 - partition\_for\_var\_log
## Rule 1.1.16 - partition\_for\_var\_log\_audit
## Rule 1.1.17 - partition\_for\_home
## Rule 3.5.3.2.1 - iptables\_default\_deny
## Rule 3.5.3.3.1 - ip6tables\_default\_deny
## Rule 4.2.3 - all\_logfile\_permissions
## Rule 4.4 - ensure\_logrotate\_permissions
Current version of the benchmark only provides the audit check operation for those rules.

There is no fix implemented, so they must be fixed manually!

See the benchmark reference on the *INTERNET RESOURCES* section for information on how to apply the fixes.

# INTERNET RESOURCES
Ubuntu 24.04 CIS Benchmark v1.0.0: https://workbench.cisecurity.org/benchmarks/18959

# SEE ALSO
**usg**(8), **usg-rules**(7), **usg-variables**(7)

# COPYRIGHT
Copyright <<YEAR_PLACEHOLDER>> Canonical Limited. All rights reserved.

The implementation of CIS rules, profiles, scripts, and other assets are based on the ComplianceAsCode open source project (https://www.open-scap.org/security-policies/scap-security-guide).

ComplianceAsCode's license file can be found in the /usr/share/ubuntu-scap-security-guides/benchmarks directory.
