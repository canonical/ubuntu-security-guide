% USG-DISA-STIG(7) usg-benchmarks-<<USG_BENCHMARKS_ALTERNATIVE_PLACEHOLDER>> <<USG_BENCHMARKS_VERSION_PLACEHOLDER>>
% Richard Maciel Costa <richard.maciel.costa@canonical.com>
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
A few rules provided by the stig profile require manual fix. 

In addition, currently the rule *permission\_local\_var\_log* is unable to prevent new log files being created with permissions that violate the DISA-STIG requirements.

Follow a list of the rules below which matches one of the cases above:

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

### Rule id: chronyd\_or\_ntpd\_set\_maxpoll
#### Title: Configure Time Service Maxpoll Interval
#### Description:

```
The maxpoll should be configured in /etc/ntp.conf or
/etc/chrony/chrony.conf to continuously poll time servers. To configure
maxpoll in /etc/ntp.conf or /etc/chrony/chrony.conf
add the following after each `server` entry:
maxpoll

NOTE: The DISA-STIG rule currently does not support `pool` or `peer` entries.
```

### Rule id: permission\_local\_var\_log
#### Title:
#### Description:

```
This rule will enforce a permission of 0640 for files inside the /var/log directory when its audit process runs.
However, any change made after the audit process ends potentially can put the system in an uncompliant-state
with regard to that rules.
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

### Rule    package\_mfetp\_installed
#### Title: Install Endpoint Security for Linux Threat Prevention
#### Description:

```
This rule requires a third-party software to be installed.
A manual fix is required if the software is not available.
```

# INTERNET RESOURCES
Ubuntu 20.04 STIG Benchmark: https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U\_CAN\_Ubuntu\_20-04\_LTS\_V1R1\_STIG.zip

# SEE ALSO
**usg**(8), **usg-rules**(7), **usg-variables**(7)

# COPYRIGHT
Copyright <<YEAR_PLACEHOLDER>> Canonical Limited. All rights reserved.

The implementation of DISA-STIG rules, profiles, scripts, and other assets are based on the ComplianceAsCode open source project (https://www.open-scap.org/security-policies/scap-security-guide).

ComplianceAsCode's license file can be found in the /usr/share/ubuntu-scap-security-guides/benchmarks directory.
