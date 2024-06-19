% USG-DISA-STIG(7) usg-benchmarks-<<USG_BENCHMARKS_ALTERNATIVE_PLACEHOLDER>> <<USG_BENCHMARKS_VERSION_PLACEHOLDER>>
% Eduardo Barretto <eduardo.barretto@canonical.com>
% Miha Purg <miha.purg@canonical.com>
% <<DATE_PLACEHOLDER>>

# NAME
usg-disa-stig - Information on DISA-STIG implementation

# INTRODUCTION
As mentioned in the **usg-rules**(8) man page, a single DISA-STIG profile is available to be audited/applied: **stig**

This man page explains the limitations of some rules which compose the stig profile.

# CUSTOMIZING VARIABLES AFFECTING THE STIG BENCHMARK IMPLEMENTATIONS
Some rules can be fine-tuned by changing their variables. However, the STIG benchmark provides some variables with phony parameters which **must be customized** so the hardening scripts can be properly applied and the audit can properly check them.

For additional information on variables, check the **usg-variables**(7) man page.

See the **usg**(8) man page to get information on how to use tailoring files to change the value of variables.

## Rules that must be customized
The list of variables below contains a brief explanation of the variables which *must be customized* and what rules they are related to.

### Rule id: var\_audispd\_remote\_server
#### Title: Remote server for audispd to send audit records
#### Description:

```
The setting for remote_server in /etc/audisp/audisp-remote.conf
```

## Rules limitations
A few rules provided by the stig profile require manual inspection and fix.

### Rule id: auditd\_offload\_logs
#### Title: Offload audit Logs to External Media
#### Description:

```
Offloading is a common process in information systems with limited audit storage capacity.
NOTE: This script is not provided by default as different consumers have different needs.

Check if there is a script in the "/etc/cron.weekly" directory that offloads audit data:
# sudo ls /etc/cron.weekly
audit-offload 
```

### Rule id: auditd\_audispd\_configure\_sufficiently\_large\_partition
#### Title: Configure a Sufficiently Large Partition for Audit Logs
#### Description:

```
The rule requires a sufficiently large partition for storing at least one week's
worth of audit logs. As this is highly dependent on the end-user's enviroment,
the check and remediation for the rule are not implemented and must be performed
manually.
```

### Rule id: is\_fips\_mode\_enabled
#### Title: Verify '/proc/sys/crypto/fips\_enabled' exists
#### Description:

```
This rule will verify if the system is in FIPS mode.
A manual fix is required in case it is not.
For more informations on how to run the system in FIPS-140-2 mode, please see
https://ubuntu.com/security/certifications/docs/fips-enablement
```

### Rule id: install\_endpoint\_security\_software
#### Title: Install an Endpoint Security Software
#### Description:

```
This rule requires a third-party software to be installed.
A manual fix is required if the software is not available.
```

### Rule id: smartcard\_pam\_enabled
#### Title: Enable Smart Card Logins in PAM
#### Description:

```
This rule requires that the pam_pkcs11.so module is added to the PAM
authentication stack. Due to potential complexity of PAM configurations,
and risk of lock-out, the automated remediation has been disabled.

Add the following to the top of the stack in /etc/pam.d/common-auth,
replacing N with the correct number of jumps:

auth     [success=N default=ignore]     pam_pkcs11.so

e.g.
auth     [success=3 default=ignore]     pam_pkcs11.so
auth     [success=2 default=ignore]     pam_unix.so nullok
auth     [success=1 default=ignore]     pam_sss.so use_first_pass
```

### Rule id: grub2\_password
#### Title: Set Boot Loader Password in grub2
#### Description:

```
To prevent hard-coded passwords, automated remediation of this rule
is not available. Remediation must be automated as a component of machine
provisioning, or performed manually.

1) Generate the password:
$ grub-mkpasswd-pbkdf2 

2) Add the following lines to /etc/grub.d/40_custom:
set superusers="root"
password_pbkdf2 root GENERATED_PASSWORD

3) Update grub
$ sudo update-grub
```

### Rule id: check\_ufw\_active
#### Title: Verify ufw Active
#### Description:

```
The UFW firewall should be enabled and active.
The rule does not enable the firewall automatically to avoid lock-out.

To remediate, run:
$ ufw enable
```

### Rule id: ufw\_rate\_limit
#### Title: ufw Must rate-limit network interfaces
#### Description:

```
This rule requires that UFW is enabled and configured to rate-limit all services.
The firewall is not configured and enabled automatically to avoid lock-out.

To remediate, determine all listening services and set the rate-limit:
$ ss -l46ut
$ ufw limit SERVICE_NAME
```

### Rule id: encrypt\_partitions
#### Title: Encrypt Partitions
#### Description:

```
The system should be configured to prevent unauthorized disclosure or
modification of all information requiring at-rest protection by using disk encryption. 

The rule presently does not perform this check and it must be done manually.
```

### Rule id: account\_temp\_expire_date
#### Title: Assign Expiration Date to Temporary Accounts
#### Description:

```
This rule is not automated as temporary accounts cannot be differentiated
from regular accounts.
```

### Rule id: temp\_passwords\_immediate\_change
#### Title: Policy Requires Immediate Change of Temporary Passwords
#### Description:

```
This rule is not automated as temporary accounts cannot be differentiated
from regular accounts.
```

### Rule id: sudo\_group\_restricted
#### Title: Ensure sudo group has only necessary members
#### Description:

```
This rule is not automated because sudo users are unique to the end-user's environment.

Verify only authorized users are in the sudo group:
$ grep sudo /etc/group  
```

### Rule id: ufw\_only\_required_services
#### Title: Only Allow Authorized Network Services in ufw
#### Description:

```
This rule is not automated because the list of authorized network services
is unique to the end-user's environment.
```

### Rule id: only\_allow\_dod\_certs
#### Title: Only Allow DoD PKI-established CAs
#### Description:

```
The rule is not automated. It requires that all certifications found in
/etc/ssl/certs are approved by the AO.
```



# INTERNET RESOURCES
Ubuntu 22.04 STIG Benchmark: https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U\_CAN\_Ubuntu\_22-04\_LTS\_V1R1\_STIG.zip

# SEE ALSO
**usg**(8), **usg-rules**(7), **usg-variables**(7)

# COPYRIGHT
Copyright <<YEAR_PLACEHOLDER>> Canonical Limited. All rights reserved.

The implementation of DISA-STIG rules, profiles, scripts, and other assets are based on the ComplianceAsCode open source project (https://www.open-scap.org/security-policies/scap-security-guide).

ComplianceAsCode's license file can be found in the /usr/share/ubuntu-scap-security-guides/benchmarks directory.
