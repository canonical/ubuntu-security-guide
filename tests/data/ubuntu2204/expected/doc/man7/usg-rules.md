% USG-RULES(7) usg-benchmarks 22.04.12
% Eduardo Barretto <eduardo.barretto@canonical.com>
% 19 September 2025

# NAME
usg-rules - usg rules list and description

# LIST OF RULES AND THEIR DESCRIPTIONS
# List of rules
## Rule id: xccdf\_org.ssgproject.content\_rule\_prefer\_64bit\_os
### Title: Prefer to use a 64-bit Operating System when supported
### Description:

```
Prefer installation of 64-bit operating systems when the CPU supports it.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_prelink\_removed
### Title: Package "prelink" Must not be Installed
### Description:

```
The prelink package can be removed with the following command:
 
 $ apt-get remove prelink
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_aide\_installed
### Title: Install AIDE
### Description:

```
The aide package can be installed with the following command:

$ apt-get install aide
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_aide\_build\_database
### Title: Build and Test AIDE Database
### Description:

```
Run the following command to generate a new database:

$ sudo aideinit

By default, the database will be written to the file

/var/lib/aide/aide.db.new.

Storing the database, the configuration file /etc/aide.conf, and the binary
/usr/bin/aide
(or hashes of these files), in a secure location (such as on read-only media) provides additional assurance about their integrity.
The newly-generated database can be installed as follows:

$ sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

To initiate a manual check, run the following command:
$ sudo /usr/bin/aide --check
If this check produces any unexpected output, investigate.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_aide\_check\_audit\_tools
### Title: Configure AIDE to Verify the Audit Tools
### Description:

```
The operating system file integrity tool must be configured to protect the integrity of the audit tools.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_aide\_disable\_silentreports
### Title: Configure AIDE To Notify Personnel if Baseline Configurations Are Altered
### Description:

```
The operating system file integrity tool must be configured to notify designated personnel of any changes to configurations.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_aide\_periodic\_cron\_checking
### Title: Configure Periodic Execution of AIDE
### Description:

```
At a minimum, AIDE should be configured to run a weekly scan.
To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab:
05 4 * * * root /usr/bin/aide --config /etc/aide/aide.conf --check
To implement a weekly execution of AIDE at 4:05am using cron, add the following line to /etc/crontab:
05 4 * * 0 root /usr/bin/aide --config /etc/aide/aide.conf --check
AIDE can be executed periodically through other means; this is merely one example.
The usage of cron's special time codes, such as  @daily and
@weekly is acceptable.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_is\_fips\_mode\_enabled
### Title: Verify '/proc/sys/crypto/fips\_enabled' exists
### Description:

```
On a system where FIPS 140-2 mode is enabled, /proc/sys/crypto/fips_enabled must exist.
To verify FIPS mode, run the following command:
cat /proc/sys/crypto/fips_enabled
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_harden\_ssh\_client\_crypto\_policy
### Title: Harden SSH client Crypto Policy
### Description:

```
Crypto Policies are means of enforcing certain cryptographic settings for selected applications including OpenSSH client.
To override the system wide crypto policy for Openssh client, place a file in the /etc/ssh/ssh_config.d/ so that it is loaded before the 05-redhat.conf. In this case it is file named 02-ospp.conf containing parameters which need to be changed with respect to the crypto policy.
This rule checks if the file exists and if it contains required parameters and values which modify the Crypto Policy.
During the parsing process, as soon as Openssh client parses some configuration option and its value, it remembers it and ignores any subsequent overrides. The customization mechanism provided by crypto policies appends eventual customizations at the end of the system wide crypto policy. Therefore, if the crypto policy customization overrides some parameter which is already configured in the system wide crypto policy, the SSH client will not honor that customized parameter.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_installed\_OS\_is\_FIPS\_certified
### Title: The Installed Operating System Is FIPS 140-2 Certified
### Description:

```
To enable processing of sensitive information the operating system must
provide certified cryptographic modules compliant with FIPS 140-2
standard.

Ubuntu Linux is supported by Canonical Ltd. As the Ubuntu Linux Vendor, Canonical Ltd. is
responsible for government certifications and standards.

Users of Ubuntu Linux either need an Ubuntu Advantage subscription or need
to be using Ubuntu Pro from a sponsored vendor in order to have access to
FIPS content supported by Canonical.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_configure\_user\_data\_backups
### Title: Configure Backups of User Data
### Description:

```
The operating system must conduct backups of user data contained
in the operating system. The operating system provides utilities for
automating backups of user data. Commercial and open-source products
are also available.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_install\_endpoint\_security\_software
### Title: Install an Endpoint Security Solution
### Description:

```
Verify that an Endpoint Security Solution has been deployed on the operating system.  
If there is not an Endpoint Security Solution deployed, this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_mcafeetp\_installed
### Title: Install McAfee Endpoint Security for Linux (ENSL)
### Description:

```
Install McAfee Endpoint Security for Linux antivirus software
which is provided for DoD systems and uses signatures to search for the
presence of viruses on the filesystem.

The mfetp package can be installed with the following command:

$ apt-get install mfetp
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_MFEhiplsm\_installed
### Title: Install the Host Intrusion Prevention System (HIPS) Module
### Description:

```
Install the McAfee Host Intrusion Prevention System (HIPS) Module if it is absolutely
necessary. If SELinux is enabled, do not install or enable this module.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_encrypt\_partitions
### Title: Encrypt Partitions
### Description:

```
Ubuntu 22.04 natively supports partition encryption through the
Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to
encrypt a partition is during installation time.

For manual installations, select the Encrypt checkbox during
partition creation to encrypt the partition. When this
option is selected the system will prompt for a passphrase to use in
decrypting the partition. The passphrase will subsequently need to be entered manually
every time the system boots.


Detailed information on encrypting partitions using LUKS or LUKS ciphers can be found on
the Ubuntu 22.04 Documentation web site:

    
    https://help.ubuntu.com/community/Full_Disk_Encryption_Howto_2019
.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_partition\_for\_dev\_shm
### Title: Ensure /dev/shm is configured
### Description:

```
The /dev/shm is a traditional shared memory concept. 
One program will create a memory portion, which other processes 
(if permitted) can access. If /dev/shm is not configured, 
tmpfs will be mounted to /dev/shm by systemd.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_partition\_for\_home
### Title: Ensure /home Located On Separate Partition
### Description:

```
If user home directories will be stored locally, create a separate partition
for /home at installation time (or migrate it later using LVM). If
/home will be mounted from another system such as an NFS server, then
creating a separate partition is not necessary at installation time, and the
mountpoint can instead be configured later.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_partition\_for\_srv
### Title: Ensure /srv Located On Separate Partition
### Description:

```
If a file server (FTP, TFTP...) is hosted locally, create a separate partition
for /srv at installation time (or migrate it later using LVM). If
/srv will be mounted from another system such as an NFS server, then
creating a separate partition is not necessary at installation time, and the
mountpoint can instead be configured later.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_partition\_for\_tmp
### Title: Ensure /tmp Located On Separate Partition
### Description:

```
The /tmp directory is a world-writable directory used
for temporary file storage. Ensure it has its own partition or
logical volume at installation time, or migrate it using LVM.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_partition\_for\_var
### Title: Ensure /var Located On Separate Partition
### Description:

```
The /var directory is used by daemons and other system
services to store frequently-changing data. Ensure that /var has its own partition
or logical volume at installation time, or migrate it using LVM.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_partition\_for\_var\_log
### Title: Ensure /var/log Located On Separate Partition
### Description:

```
System logs are stored in the /var/log directory.

Ensure that /var/log has its own partition or logical
volume at installation time, or migrate it using LVM.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_partition\_for\_var\_log\_audit
### Title: Ensure /var/log/audit Located On Separate Partition
### Description:

```
Audit logs are stored in the /var/log/audit directory.

Ensure that /var/log/audit has its own partition or logical
volume at installation time, or migrate it using LVM.
Make absolutely certain that it is large enough to store all
audit logs that will be created by the auditing daemon.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_partition\_for\_var\_tmp
### Title: Ensure /var/tmp Located On Separate Partition
### Description:

```
The /var/tmp directory is a world-writable directory used
for temporary file storage. Ensure it has its own partition or
logical volume at installation time, or migrate it using LVM.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_gdm\_removed
### Title: Remove the GDM Package Group
### Description:

```
By removing the gdm3 package, the system no longer has GNOME installed

installed. If X Windows is not installed then the system cannot boot into graphical user mode.
This prevents the system from being accidentally or maliciously booted into a graphical.target
mode. To do so, run the following command:

$ sudo apt remove gdm3
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_enable\_dconf\_user\_profile
### Title: Configure GNOME3 DConf User Profile
### Description:

```
By default, DConf provides a standard user profile. This profile contains a list
of DConf configuration databases. The user profile and database always take the
highest priority. As such the DConf User profile should always exist and be
configured correctly.


To make sure that the gdm profile is configured correctly, the /etc/dconf/profile/gdm
should be set as follows:
user-db:user
system-db:gdm

To make sure that the user profile is configured correctly, the /etc/dconf/profile/user
should be set as follows:
user-db:user
system-db:local

```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dconf\_gnome\_disable\_user\_list
### Title: Disable the GNOME3 Login User List
### Description:

```
In the default graphical environment, users logging directly into the
system are greeted with a login screen that displays all known users.
This functionality should be disabled by setting disable-user-list
to true.

To disable, add or edit disable-user-list to
/etc/dconf/db/gdm.d/00-security-settings. For example:
[org/gnome/login-screen]
disable-user-list=true
Once the setting has been added, add a lock to
/etc/dconf/db/gdm.d/locks/00-security-settings-lock to prevent
user modification. For example:
/org/gnome/login-screen/disable-user-list
After the settings have been set, run dconf update.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_gnome\_gdm\_disable\_xdmcp
### Title: Disable XDMCP in GDM
### Description:

```
XDMCP is an unencrypted protocol, and therefore, presents a security risk, see e.g.
XDMCP Gnome docs.

To disable XDMCP support in Gnome, set Enable to false under the [xdmcp] configuration section in /etc/gdm/custom.conf. For example:

[xdmcp]
Enable=false

```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dconf\_gnome\_disable\_automount
### Title: Disable GNOME3 Automounting
### Description:

```
The system's default desktop environment, GNOME3, will mount
devices and removable media (such as DVDs, CDs and USB flash drives) whenever
they are inserted into the system. To disable automount within GNOME3, add or set
automount to false in /etc/dconf/db/local.d/00-security-settings.
For example:
[org/gnome/desktop/media-handling]
automount=false
Once the settings have been added, add a lock to
/etc/dconf/db/local.d/locks/00-security-settings-lock to prevent user modification.
For example:
/org/gnome/desktop/media-handling/automount
After the settings have been set, run dconf update.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dconf\_gnome\_disable\_automount\_open
### Title: Disable GNOME3 Automount Opening
### Description:

```
The system's default desktop environment, GNOME3, will mount
devices and removable media (such as DVDs, CDs and USB flash drives) whenever
they are inserted into the system. To disable automount-open within GNOME3, add or set
automount-open to false in /etc/dconf/db/local.d/00-security-settings.
For example:
[org/gnome/desktop/media-handling]
automount-open=false
Once the settings have been added, add a lock to
/etc/dconf/db/local.d/locks/00-security-settings-lock to prevent user modification.
For example:
/org/gnome/desktop/media-handling/automount-open
After the settings have been set, run dconf update.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dconf\_gnome\_disable\_autorun
### Title: Disable GNOME3 Automount running
### Description:

```
The system's default desktop environment, GNOME3, will mount
devices and removable media (such as DVDs, CDs and USB flash drives) whenever
they are inserted into the system. To disable autorun-never within GNOME3, add or set
autorun-never to true in /etc/dconf/db/local.d/00-security-settings.
For example:
[org/gnome/desktop/media-handling]
autorun-never=true
Once the settings have been added, add a lock to
/etc/dconf/db/local.d/locks/00-security-settings-lock to prevent user modification.
For example:
/org/gnome/desktop/media-handling/autorun-never
After the settings have been set, run dconf update.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dconf\_gnome\_screensaver\_idle\_delay
### Title: Set GNOME3 Screensaver Inactivity Timeout
### Description:

```
The idle time-out value for inactivity in the GNOME3 desktop is configured via the idle-delay
setting must be set under an appropriate configuration file(s) in the /etc/dconf/db/local.d directory
and locked in /etc/dconf/db/local.d/locks directory to prevent user modification.

For example, to configure the system for a 15 minute delay, add the following to
/etc/dconf/db/local.d/00-security-settings:
[org/gnome/desktop/session]
idle-delay=uint32 900
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dconf\_gnome\_screensaver\_lock\_delay
### Title: Set GNOME3 Screensaver Lock Delay After Activation Period
### Description:

```
To activate the locking delay of the screensaver in the GNOME3 desktop when
the screensaver is activated, add or set lock-delay to uint32  in
/etc/dconf/db/local.d/00-security-settings. For example:
[org/gnome/desktop/screensaver]
lock-delay=uint32 
After the settings have been set, run dconf update.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dconf\_gnome\_screensaver\_lock\_enabled
### Title: Enable GNOME3 Screensaver Lock After Idle Period
### Description:

```
To activate locking of the screensaver in the GNOME3 desktop when it is activated,
add or set lock-enabled to true in
/etc/dconf/db/local.d/00-security-settings. For example:
[org/gnome/desktop/screensaver]
lock-enabled=true

Once the settings have been added, add a lock to
/etc/dconf/db/local.d/locks/00-security-settings-lock to prevent user modification.
For example:
/org/gnome/desktop/screensaver/lock-enabled
After the settings have been set, run dconf update.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dconf\_gnome\_disable\_ctrlaltdel\_reboot
### Title: Disable Ctrl-Alt-Del Reboot Key Sequence in GNOME3
### Description:

```
By default, GNOME will reboot the system if the
Ctrl-Alt-Del key sequence is pressed.

To configure the system to ignore the Ctrl-Alt-Del key sequence
from the Graphical User Interface (GUI) instead of rebooting the system,
add or set logout to [''] in
/etc/dconf/db/local.d/00-security-settings. For example:
[org/gnome/settings-daemon/plugins/media-keys]
logout=['']
Once the settings have been added, add a lock to
/etc/dconf/db/local.d/locks/00-security-settings-lock to prevent
user modification. For example:
/org/gnome/settings-daemon/plugins/media-keys/logout
After the settings have been set, run dconf update.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_sudo\_installed
### Title: Install sudo Package
### Description:

```
The sudo package can be installed with the following command:

$ apt-get install sudo
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sudo\_add\_noexec
### Title: Ensure Privileged Escalated Commands Cannot Execute Other Commands - sudo NOEXEC
### Description:

```
The sudo NOEXEC tag, when specified, prevents user executed
commands from executing other commands, like a shell for example.
This should be enabled by making sure that the NOEXEC tag exists in
/etc/sudoers configuration file or any sudo configuration snippets
in /etc/sudoers.d/.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sudo\_add\_requiretty
### Title: Ensure Only Users Logged In To Real tty Can Execute Sudo - sudo requiretty
### Description:

```
The sudo requiretty tag, when specified, will only execute sudo
commands from users logged in to a real tty.
This should be enabled by making sure that the requiretty tag exists in
/etc/sudoers configuration file or any sudo configuration snippets
in /etc/sudoers.d/.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sudo\_add\_use\_pty
### Title: Ensure Only Users Logged In To Real tty Can Execute Sudo - sudo use\_pty
### Description:

```
The sudo use_pty tag, when specified, will only execute sudo
commands from users logged in to a real tty.
This should be enabled by making sure that the use_pty tag exists in
/etc/sudoers configuration file or any sudo configuration snippets
in /etc/sudoers.d/.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sudo\_custom\_logfile
### Title: Ensure Sudo Logfile Exists - sudo logfile
### Description:

```
A custom log sudo file can be configured with the 'logfile' tag. This rule configures
a sudo custom logfile at the default location suggested by CIS, which uses
/var/log/sudo.log.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sudo\_remove\_no\_authenticate
### Title: Ensure Users Re-Authenticate for Privilege Escalation - sudo !authenticate
### Description:

```
The sudo !authenticate option, when specified, allows a user to execute commands using
sudo without having to authenticate. This should be disabled by making sure that the
!authenticate option does not exist in /etc/sudoers configuration file or
any sudo configuration snippets in /etc/sudoers.d/.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sudo\_remove\_nopasswd
### Title: Ensure Users Re-Authenticate for Privilege Escalation - sudo NOPASSWD
### Description:

```
The sudo NOPASSWD tag, when specified, allows a user to execute
commands using sudo without having to authenticate. This should be disabled
by making sure that the NOPASSWD tag does not exist in
/etc/sudoers configuration file or any sudo configuration snippets
in /etc/sudoers.d/.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sudo\_require\_authentication
### Title: Ensure Users Re-Authenticate for Privilege Escalation - sudo
### Description:

```
The sudo NOPASSWD and !authenticate option, when
specified, allows a user to execute commands using sudo without having to
authenticate. This should be disabled by making sure that
NOPASSWD and/or !authenticate do not exist in
/etc/sudoers configuration file or any sudo configuration snippets
in /etc/sudoers.d/."
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sudo\_require\_reauthentication
### Title: Require Re-Authentication When Using the sudo Command
### Description:

```
The sudo timestamp_timeout tag sets the amount of time sudo password prompt waits.
The default timestamp_timeout value is 5 minutes.
The timestamp_timeout should be configured by making sure that the
timestamp_timeout tag exists in
/etc/sudoers configuration file or any sudo configuration snippets
in /etc/sudoers.d/.
If the value is set to an integer less than 0, the user's time stamp will not expire
and the user will not have to re-authenticate for privileged actions until the user's session is terminated.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sudo\_vdsm\_nopasswd
### Title: Only the VDSM User Can Use sudo NOPASSWD
### Description:

```
The sudo NOPASSWD tag, when specified, allows a user to execute commands using sudo without having to authenticate. Only the vdsm user should have this capability in any sudo configuration snippets in /etc/sudoers.d/.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sudoers\_explicit\_command\_args
### Title: Explicit arguments in sudo specifications
### Description:

```
All commands in the sudoers file must strictly specify the arguments allowed to be used for a given user.
If the command is supposed to be executed only without arguments, pass "" as an argument in the corresponding user specification.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sudoers\_no\_command\_negation
### Title: Don't define allowed commands in sudoers by means of exclusion
### Description:

```
Policies applied by sudo through the sudoers file should not involve negation.

Each user specification in the sudoers file contains a comma-delimited list of command specifications.
The definition can make use glob patterns, as well as of negations.
Indirect definition of those commands by means of exclusion of a set of commands is trivial to bypass, so it is not allowed to use such constructs.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sudoers\_no\_root\_target
### Title: Don't target root user in the sudoers file
### Description:

```
The targeted users of a user specification should be, as much as possible, non privileged users (i.e.: non-root).

User specifications have to explicitly list the runas spec (i.e. the list of target users that can be impersonated), and ALL or root should not be used.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_gnutls-utils\_installed
### Title: Ensure gnutls-utils is installed
### Description:

```
The gnutls-utils package can be installed with the following command:

$ apt-get install gnutls-utils
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_nss-tools\_installed
### Title: Ensure nss-tools is installed
### Description:

```
The nss-tools package can be installed with the following command:

$ apt-get install nss-tools
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_clean\_components\_post\_updating
### Title: Ensure apt\_get Removes Previous Package Versions
### Description:

```
apt_get should be configured to remove previous software components after
new versions have been installed. To configure apt_get to remove the

previous software components after updating, set the ::Remove-Unused-Dependencies and
::Remove-Unused-Kernel-Packages


to true in /etc/apt/apt.conf.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_banner\_etc\_issue
### Title: Modify the System Login Banner
### Description:

```
To configure the system login banner edit /etc/issue. Replace the
default text with a message compliant with the local site policy or a legal
disclaimer.


The DoD required text is either:

You are accessing a U.S. Government (USG) Information System (IS) that
is provided for USG-authorized use only. By using this IS (which includes
any device attached to this IS), you consent to the following conditions:


OR:

I've read & consent to terms in IS user agreem't.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_banner\_etc\_issue\_net
### Title: Modify the System Login Banner for Remote Connections
### Description:

```
To configure the system login banner edit /etc/issue.net. Replace the
default text with a message compliant with the local site policy or a legal
disclaimer.

The DoD required text is either:

You are accessing a U.S. Government (USG) Information System (IS) that
is provided for USG-authorized use only. By using this IS (which includes
any device attached to this IS), you consent to the following conditions:


OR:

I've read & consent to terms in IS user agreem't.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_banner\_etc\_motd
### Title: Modify the System Message of the Day Banner
### Description:

```
To configure the system message banner edit /etc/motd. Replace the
default text with a message compliant with the local site policy or a legal
disclaimer.

The DoD required text is either:

You are accessing a U.S. Government (USG) Information System (IS) that
is provided for USG-authorized use only. By using this IS (which includes
any device attached to this IS), you consent to the following conditions:


OR:

I've read & consent to terms in IS user agreem't.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_issue
### Title: Verify Group Ownership of System Login Banner
### Description:

```
To properly set the group owner of /etc/issue, run the command:
$ sudo chgrp root /etc/issue
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_issue\_net
### Title: Verify Group Ownership of System Login Banner for Remote Connections
### Description:

```
To properly set the group owner of /etc/issue.net, run the command:
$ sudo chgrp root /etc/issue.net
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_motd
### Title: Verify Group Ownership of Message of the Day Banner
### Description:

```
To properly set the group owner of /etc/motd, run the command:
$ sudo chgrp root /etc/motd
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_issue
### Title: Verify ownership of System Login Banner
### Description:

```
To properly set the owner of /etc/issue, run the command:
$ sudo chown root /etc/issue 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_issue\_net
### Title: Verify ownership of System Login Banner for Remote Connections
### Description:

```
To properly set the owner of /etc/issue.net, run the command:
$ sudo chown root /etc/issue.net 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_motd
### Title: Verify ownership of Message of the Day Banner
### Description:

```
To properly set the owner of /etc/motd, run the command:
$ sudo chown root /etc/motd 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_issue
### Title: Verify permissions on System Login Banner
### Description:

```
To properly set the permissions of /etc/issue, run the command:
$ sudo chmod 0644 /etc/issue
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_issue\_net
### Title: Verify permissions on System Login Banner for Remote Connections
### Description:

```
To properly set the permissions of /etc/issue.net, run the command:
$ sudo chmod 0644 /etc/issue.net
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_motd
### Title: Verify permissions on Message of the Day Banner
### Description:

```
To properly set the permissions of /etc/motd, run the command:
$ sudo chmod 0644 /etc/motd
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dconf\_gnome\_banner\_enabled
### Title: Enable GNOME3 Login Warning Banner
### Description:

```
In the default graphical environment, displaying a login warning banner
in the GNOME Display Manager's login screen can be enabled on the login
screen by setting banner-message-enable to true.

To enable, add or edit banner-message-enable to
/etc/dconf/db/gdm.d/00-security-settings. For example:
[org/gnome/login-screen]
banner-message-enable=true
Once the setting has been added, add a lock to
/etc/dconf/db/gdm.d/locks/00-security-settings-lock to prevent user modification.
For example:
/org/gnome/login-screen/banner-message-enable
After the settings have been set, run dconf update.
The banner text must also be set.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dconf\_gnome\_login\_banner\_text
### Title: Set the GNOME3 Login Warning Banner Text
### Description:

```
In the default graphical environment, configuring the login warning banner text
in the GNOME Display Manager's login screen can be configured on the login
screen by setting banner-message-text to '
where APPROVED_BANNER is the approved banner for your environment.

To enable, add or edit banner-message-text to

/etc/gdm3/greeter.dconf-defaults. For example:
[org/gnome/login-screen]
banner-message-text='

After the settings have been set, run dconf update.
When entering a warning banner that spans several lines, remember
to begin and end the string with ' and use \n for new lines.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_pam\_pwquality\_installed
### Title: Install pam\_pwquality Package
### Description:

```
The libpam-pwquality package can be installed with the following command:

$ apt-get install libpam-pwquality
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_disallow\_bypass\_password\_sudo
### Title: Disallow Configuration to Bypass Password Requirements for Privilege Escalation
### Description:

```
Verify the operating system is not configured to bypass password requirements for privilege
escalation. Check the configuration of the "/etc/pam.d/sudo" file with the following command:
$ sudo grep pam_succeed_if /etc/pam.d/sudo
If any occurrences of "pam_succeed_if" is returned from the command, this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_display\_login\_attempts
### Title: Ensure PAM Displays Last Logon/Access Notification
### Description:

```
To configure the system to notify users of last logon/access
using pam_lastlog, add or correct the pam_lastlog
settings in
/etc/pam.d/login to read as follows:
session     required pam_lastlog.so showfailed
And make sure that the silent option is not set for
pam_lastlog module.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_account\_passwords\_pam\_faillock\_audit
### Title: Account Lockouts Must Be Logged
### Description:

```
PAM faillock locks an account due to excessive password failures, this event must be logged.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_account\_passwords\_pam\_faillock\_dir
### Title: Account Lockouts Must Persist
### Description:

```
By setting a `dir` in the faillock configuration account lockouts will persist across reboots.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_unix\_remember
### Title: Limit Password Reuse
### Description:

```
Do not allow users to reuse recent passwords. This can be accomplished by using the
remember option for the pam_unix or pam_pwhistory PAM modules.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_passwords\_pam\_faildelay\_delay
### Title: Enforce Delay After Failed Logon Attempts
### Description:

```
To configure the system to introduce a delay after failed logon attempts,
add or correct the pam_faildelay settings in
/etc/pam.d/common-auth to make sure its delay parameter
is at least  or greater. For example:
auth required pam_faildelay.so delay=
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_passwords\_pam\_faillock\_audit
### Title: Account Lockouts Must Be Logged
### Description:

```
PAM faillock locks an account due to excessive password failures, this event must be logged.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_passwords\_pam\_faillock\_deny
### Title: Lock Accounts After Failed Password Attempts
### Description:

```
This rule configures the system to lock out accounts after a number of incorrect login attempts
using pam_faillock.so.

pam_faillock.so module requires multiple entries in pam files. These entries must be carefully
defined to work as expected.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_passwords\_pam\_faillock\_interval
### Title: Set Interval For Counting Failed Password Attempts
### Description:

```
Utilizing pam_faillock.so, the fail_interval directive configures the system
to lock out an account after a number of incorrect login attempts within a specified time
period.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_passwords\_pam\_faillock\_silent
### Title: Do Not Show System Messages When Unsuccessful Logon Attempts Occur
### Description:

```
This rule ensures the system prevents informative messages from being presented to the user
pertaining to logon information after a number of incorrect login attempts using
pam_faillock.so.

pam_faillock.so module requires multiple entries in pam files. These entries must be carefully
defined to work as expected. In order to avoid errors when manually editing these files, it is
recommended to use the appropriate tools, such as authselect or authconfig,
depending on the OS version.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_passwords\_pam\_faillock\_unlock\_time
### Title: Set Lockout Time for Failed Password Attempts
### Description:

```
This rule configures the system to lock out accounts during a specified time period after a
number of incorrect login attempts using pam_faillock.so.

pam_faillock.so module requires multiple entries in pam files. These entries must be carefully
defined to work as expected. In order to avoid any errors when manually editing these files,
it is recommended to use the appropriate tools, such as authselect or authconfig,
depending on the OS version.

If unlock_time is set to 0, manual intervention by an administrator is required
to unlock a user. This should be done using the faillock tool.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_dcredit
### Title: Ensure PAM Enforces Password Requirements - Minimum Digit Characters
### Description:

```
The pam_pwquality module's dcredit parameter controls requirements for
usage of digits in a password. When set to a negative number, any password will be required to
contain that many digits. When set to a positive number, pam_pwquality will grant +1 additional
length credit for each digit. Modify the dcredit setting in
/etc/security/pwquality.conf to require the use of a digit in passwords.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_dictcheck
### Title: Ensure PAM Enforces Password Requirements - Prevent the Use of Dictionary Words
### Description:

```
The pam_pwquality module's dictcheck check if passwords contains dictionary words. When
dictcheck is set to 1 passwords will be checked for dictionary words.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_difok
### Title: Ensure PAM Enforces Password Requirements - Minimum Different Characters
### Description:

```
The pam_pwquality module's difok parameter sets the number of characters
in a password that must not be present in and old password during a password change.

Modify the difok setting in /etc/security/pwquality.conf
to equal  to require differing characters
when changing passwords.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_enforcing
### Title: Ensure PAM Enforces Password Requirements - Enforcing
### Description:

```
Verify that the operating system uses "pwquality" to enforce the
password complexity rules.

Verify the pwquality module is being enforced by operating system by
running the following command:

$ grep -i enforcing /etc/security/pwquality.conf
enforcing = 1


If the value of "enforcing" is not "1" or the line is commented out,
this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_lcredit
### Title: Ensure PAM Enforces Password Requirements - Minimum Lowercase Characters
### Description:

```
The pam_pwquality module's lcredit parameter controls requirements for
usage of lowercase letters in a password. When set to a negative number, any password will be required to
contain that many lowercase characters. When set to a positive number, pam_pwquality will grant +1 additional
length credit for each lowercase character. Modify the lcredit setting in
/etc/security/pwquality.conf to require the use of a lowercase character in passwords.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_minclass
### Title: Ensure PAM Enforces Password Requirements - Minimum Different Categories
### Description:

```
The pam_pwquality module's minclass parameter controls
requirements for usage of different character classes, or types, of character
that must exist in a password before it is considered valid. For example,
setting this value to three (3) requires that any password must have characters
from at least three different categories in order to be approved. The default
value is zero (0), meaning there are no required classes. There are four
categories available:

* Upper-case characters
* Lower-case characters
* Digits
* Special characters (for example, punctuation)

Modify the minclass setting in /etc/security/pwquality.conf entry
to require 
differing categories of characters when changing passwords.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_minlen
### Title: Ensure PAM Enforces Password Requirements - Minimum Length
### Description:

```
The pam_pwquality module's minlen parameter controls requirements for
minimum characters required in a password. Add minlen=
after pam_pwquality to set minimum password length requirements.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_ocredit
### Title: Ensure PAM Enforces Password Requirements - Minimum Special Characters
### Description:

```
The pam_pwquality module's ocredit= parameter controls requirements for
usage of special (or "other") characters in a password. When set to a negative number,
any password will be required to contain that many special characters.
When set to a positive number, pam_pwquality will grant +1
additional length credit for each special character. Modify the ocredit setting
in /etc/security/pwquality.conf to equal 
to require use of a special character in passwords.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_retry
### Title: Ensure PAM Enforces Password Requirements - Authentication Retry Prompts Permitted Per-Session
### Description:

```
To configure the number of retry prompts that are permitted per-session:

Edit the pam_pwquality.so statement in

/etc/pam.d/common-password to show


retry=, or a lower value if site
policy is more restrictive. The DoD requirement is a maximum of 3 prompts
per session.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_ucredit
### Title: Ensure PAM Enforces Password Requirements - Minimum Uppercase Characters
### Description:

```
The pam_pwquality module's ucredit= parameter controls requirements for
usage of uppercase letters in a password. When set to a negative number, any password will be required to
contain that many uppercase characters. When set to a positive number, pam_pwquality will grant +1 additional
length credit for each uppercase character. Modify the ucredit setting in
/etc/security/pwquality.conf to require the use of an uppercase character in passwords.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_password\_hashing\_algorithm\_logindefs
### Title: Set Password Hashing Algorithm in /etc/login.defs
### Description:

```
In /etc/login.defs, add or correct the following line to ensure
the system will use  as the hashing algorithm:
ENCRYPT_METHOD 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_password\_hashing\_algorithm\_systemauth
### Title: Set PAM''s Password Hashing Algorithm
### Description:

```
The PAM system service can be configured to only store encrypted
representations of passwords. In "/etc/pam.d/common-password", the
password section of the file controls which PAM modules execute
during a password change. Set the pam_unix.so module in the
password section to include the argument sha512, as shown
below:


password    [success=1 default=ignore]   pam_unix.so sha512 


This will help ensure when local users change their passwords, hashes for
the new passwords will be generated using the SHA-512 algorithm. This is
the default.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_disable\_ctrlaltdel\_burstaction
### Title: Disable Ctrl-Alt-Del Burst Action
### Description:

```
By default, SystemD will reboot the system if the Ctrl-Alt-Del
key sequence is pressed Ctrl-Alt-Delete more than 7 times in 2 seconds.

To configure the system to ignore the CtrlAltDelBurstAction

setting, add or modify the following to /etc/systemd/system.conf:
CtrlAltDelBurstAction=none
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_disable\_ctrlaltdel\_reboot
### Title: Disable Ctrl-Alt-Del Reboot Activation
### Description:

```
By default, SystemD will reboot the system if the Ctrl-Alt-Del
key sequence is pressed.

To configure the system to ignore the Ctrl-Alt-Del key sequence from the

command line instead of rebooting the system, do either of the following:
ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target
or
systemctl mask ctrl-alt-del.target

Do not simply delete the /usr/lib/systemd/system/ctrl-alt-del.service file,
as this file may be restored during future system updates.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_vlock\_installed
### Title: Check that vlock is installed to allow session locking
### Description:

```
The Ubuntu 22.04 operating system must have vlock installed to allow for session locking.


The vlock package can be installed with the following command:

$ apt-get install vlock
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_opensc\_installed
### Title: Install the opensc Package For Multifactor Authentication
### Description:

```
The opensc-pkcs11 package can be installed with the following command:

$ apt-get install opensc-pkcs11
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_install\_smartcard\_packages
### Title: Install Smart Card Packages For Multifactor Authentication
### Description:

```
Configure the operating system to implement multifactor authentication by
installing the required package with the following command:

The libpam-pkcs11 package can be installed with the following command:

$ apt-get install libpam-pkcs11
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_smartcard\_configure\_ca
### Title: Configure Smart Card Certificate Authority Validation
### Description:

```
Configure the operating system to do certificate status checking for PKI
authentication. Modify all of the cert_policy lines in
/etc/pam_pkcs11/pam_pkcs11.conf to include ca like so:
cert_policy = ca, ocsp_on, signature;
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_smartcard\_configure\_cert\_checking
### Title: Configure Smart Card Certificate Status Checking
### Description:

```
Configure the operating system to do certificate status checking for PKI
authentication. Modify all of the cert_policy lines in
/etc/pam_pkcs11/pam_pkcs11.conf to include ocsp_on like so:
cert_policy = ca, ocsp_on, signature;
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_smartcard\_configure\_crl
### Title: Configure Smart Card Local Cache of Revocation Data
### Description:

```
Configure the operating system for PKI-based authentication to use
local revocation data when unable to access the network to obtain it
remotely. Modify all of the cert_policy lines in
/etc/pam_pkcs11/pam_pkcs11.conf to include crl_auto
or crl_offline like so:
cert_policy = ca,signature,ocsp_on,crl_auto;
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_smartcard\_pam\_enabled
### Title: Enable Smart Card Logins in PAM
### Description:

```
This requirement only applies to components where this is specific to the
function of the device or has the concept of an organizational user (e.g.,
VPN, proxy capability). This does not apply to authentication for the
purpose of configuring the device itself (management).

Check that the pam_pkcs11.so option is configured in the
etc/pam.d/common-auth file with the following command:

# grep pam_pkcs11.so /etc/pam.d/common-auth

auth sufficient pam_pkcs11.so

For general information about enabling smart card authentication, consult
the documentation at:


```

## Rule id: xccdf\_org.ssgproject.content\_rule\_verify\_use\_mappers
### Title: Verify that 'use\_mappers' is set to 'pwent' in PAM
### Description:

```
The operating system must map the authenticated identity to the user or
group account for PKI-based authentication.

Verify that use_mappers is set to pwent in
/etc/pam_pkcs11/pam_pkcs11.conf file with the following command:

$ grep ^use_mappers /etc/pam_pkcs11/pam_pkcs11.conf

use_mappers = pwent
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_account\_unique\_id
### Title: Ensure All Accounts on the System Have Unique User IDs
### Description:

```
Change user IDs (UIDs), or delete accounts, so each has a unique name.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_group\_unique\_id
### Title: Ensure All Groups on the System Have Unique Group ID
### Description:

```
Change the group name or delete groups, so each has a unique id.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_group\_unique\_name
### Title: Ensure All Groups on the System Have Unique Group Names
### Description:

```
Change the group name or delete groups, so each has a unique name.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_account\_disable\_post\_pw\_expiration
### Title: Set Account Expiration Following Inactivity
### Description:

```
To specify the number of days after a password expires (which
signifies inactivity) until an account is permanently disabled, add or correct
the following line in /etc/default/useradd:
INACTIVE=
If a password is currently on the verge of expiration, then

day(s) remain(s) until the account is automatically
disabled. However, if the password will not expire for another 60 days, then 60
days plus  day(s) could
elapse until the account would be automatically disabled. See the
useradd man page for more information.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_account\_temp\_expire\_date
### Title: Assign Expiration Date to Temporary Accounts
### Description:

```
Temporary accounts are established as part of normal account activation
procedures when there is a need for short-term accounts. In the event
temporary accounts are required, configure the system to
terminate them after a documented time period. For every temporary account, run the following command to set an expiration date on
it, substituting  and 
appropriately:
$ sudo chage -E 
 indicates the documented expiration date for the
account. For U.S. Government systems, the operating system must be
configured to automatically terminate these types of accounts after a
period of 72 hours.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_account\_unique\_name
### Title: Ensure All Accounts on the System Have Unique Names
### Description:

```
Ensure accounts on the system have unique names.

To ensure all accounts have unique names, run the following command:
$ sudo getent passwd | awk -F: '{ print $1}' | uniq -d
If a username is returned, change or delete the username.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_account\_use\_centralized\_automated\_auth
### Title: Use Centralized and Automated Authentication
### Description:

```
Implement an automated system for managing user accounts that minimizes the
risk of errors, either intentional or deliberate. This system
should integrate with an existing enterprise user management system, such as
one based on Identity Management tools such as Active Directory, Kerberos,
Directory Server, etc.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ensure\_shadow\_group\_empty
### Title: Ensure shadow group is empty
### Description:

```
The shadow group allows system programs which require access the ability
to read the /etc/shadow file. No users should be assigned to the shadow group.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_policy\_temp\_passwords\_immediate\_change
### Title: Policy Requires Immediate Change of Temporary Passwords
### Description:

```
Temporary passwords for Ubuntu 22.04 operating system logons must
require an immediate change to a permanent password.

Verify that a policy exists that ensures when a user is created, it is
creating using a method that forces a user to change their password upon
their next login.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_maximum\_age\_login\_defs
### Title: Set Password Maximum Age
### Description:

```
To specify password maximum age for new accounts,
edit the file /etc/login.defs
and add or correct the following line:
PASS_MAX_DAYS 
A value of 180 days is sufficient for many environments.
The DoD requirement is 60.
The profile requirement is .
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_minimum\_age\_login\_defs
### Title: Set Password Minimum Age
### Description:

```
To specify password minimum age for new accounts,
edit the file /etc/login.defs
and add or correct the following line:
PASS_MIN_DAYS 
A value of 1 day is considered sufficient for many
environments. The DoD requirement is 1.
The profile requirement is .
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_minlen\_login\_defs
### Title: Set Password Minimum Length in login.defs
### Description:

```
To specify password length requirements for new accounts, edit the file
/etc/login.defs and add or correct the following line:
PASS_MIN_LEN 

The DoD requirement is 15.
The FISMA requirement is 12.
The profile requirement is
.
If a program consults /etc/login.defs and also another PAM module
(such as pam_pwquality) during a password change operation, then
the most restrictive must be satisfied. See PAM section for more
information about enforcing password quality requirements.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_set\_max\_life\_existing
### Title: Set Existing Passwords Maximum Age
### Description:

```
Configure non-compliant accounts to enforce a -day maximum password lifetime
restriction by running the following command:
$ sudo chage -M 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_set\_min\_life\_existing
### Title: Set Existing Passwords Minimum Age
### Description:

```
Configure non-compliant accounts to enforce a 24 hours/1 day minimum password
lifetime by running the following command:
$ sudo chage -m 1 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_warn\_age\_login\_defs
### Title: Set Password Warning Age
### Description:

```
To specify how many days prior to password
expiration that a warning will be issued to users,
edit the file /etc/login.defs and add or correct
 the following line:
PASS_WARN_AGE 
The DoD requirement is 7.
The profile requirement is .
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_all\_shadowed
### Title: Verify All Account Password Hashes are Shadowed
### Description:

```
If any password hashes are stored in /etc/passwd (in the second field,
instead of an x or *), the cause of this misconfiguration should be
investigated. The account should have its password reset and the hash should be
properly stored, or the account should be deleted entirely.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_last\_change\_is\_in\_past
### Title: Ensure all users last password change date is in the past
### Description:

```
All users should have a password change date in the past.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ensure\_sudo\_group\_restricted
### Title: Ensure sudo group has only necessary members
### Description:

```
Developers and implementers can increase the assurance in security
functions by employing well-defined security policy models; structured,
disciplined, and rigorous hardware and software development techniques;
and sound system/security engineering principles. Implementation may
include isolation of memory space and libraries.

The Ubuntu operating system restricts access to security functions
through the use of access control mechanisms and by implementing least
privilege capabilities.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_gid\_passwd\_group\_same
### Title: All GIDs referenced in /etc/passwd must be defined in /etc/group
### Description:

```
Add a group to the system for each GID referenced without a corresponding group.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_duplicate\_uids
### Title: Ensure no duplicate UIDs exist
### Description:

```
Although the useradd program will not let you create a duplicate User ID (UID),
it is possible for an administrator to manually edit the /etc/passwd file
and change the UID field. Users must be assigned unique UIDs for
accountability and to ensure appropriate access protections.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_empty\_passwords
### Title: Prevent Login to Accounts With Empty Password
### Description:

```
If an account is configured for password authentication
but does not have an assigned password, it may be possible to log
into the account without authentication. Remove any instances of the
nullok in

/etc/pam.d/common-password

to prevent logins with empty passwords.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_empty\_passwords\_etc\_shadow
### Title: Ensure There Are No Accounts With Blank or Null Passwords
### Description:

```
Check the "/etc/shadow" file for blank passwords with the
following command:
$ sudo awk -F: '!$2 {print $1}' /etc/shadow
If the command returns any results, this is a finding.
Configure all accounts on the system to have a password or lock
the account with the following commands:
Perform a password reset:
$ sudo passwd [username]
Lock an account:
$ sudo passwd -l [username]
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_forward\_files
### Title: Verify No .forward Files Exist
### Description:

```
The .forward file specifies an email address to forward the user's mail to.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_netrc\_files
### Title: Verify No netrc Files Exist
### Description:

```
The .netrc files contain login information
used to auto-login into FTP servers and reside in the user's home
directory. These files may contain unencrypted passwords to
remote FTP servers making them susceptible to access by unauthorized
users and should not be used.  Any .netrc files should be removed.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_no\_uid\_except\_zero
### Title: Verify Only Root Has UID 0
### Description:

```
If any account other than root has a UID of 0, this misconfiguration should
be investigated and the accounts other than root should be removed or have
their UID changed.

If the account is associated with system commands or applications the UID
should be changed to one greater than "0" but less than "1000."
Otherwise assign a UID greater than "1000" that has not already been
assigned.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_root\_gid\_zero
### Title: Verify Root Has A Primary GID 0
### Description:

```
The root user should have a primary group of 0.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ensure\_pam\_wheel\_group\_empty
### Title: Ensure the Group Used by pam\_wheel Module Exists on System and is Empty
### Description:

```
Ensure that the group 
referenced by the pam_wheel  group parameter exists and has no
members. This ensures that no user can run commands with altered
privileges through the su command.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ensure\_root\_password\_configured
### Title: Ensure Authentication Required for Single User Mode
### Description:

```
Single user mode is used for recovery when the system detects an
issue during boot or by manual selection from the bootloader.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_direct\_root\_logins
### Title: Direct root Logins Not Allowed
### Description:

```
To further limit access to the root account, administrators
can disable root logins at the console by editing the /etc/securetty file.
This file lists all devices the root user is allowed to login to. If the file does
not exist at all, the root user can login through any communication device on the
system, whether via the console or via a raw network interface. This is dangerous
as user can login to the system as root via Telnet, which sends the password in
plain text over the network. By default, Ubuntu 22.04's
/etc/securetty file only allows the root user to login at the console
physically attached to the system. To prevent root from logging in, remove the
contents of this file. To prevent direct root logins, remove the contents of this
file by typing the following command:

$ sudo echo > /etc/securetty

```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_password\_auth\_for\_systemaccounts
### Title: Ensure that System Accounts Are Locked
### Description:

```
Some accounts are not associated with a human user of the system, and exist to
perform some administrative function. An attacker should not be able to log into
these accounts.

System accounts are those user accounts with a user ID
less than UID_MIN, where value of the UID_MIN directive is set in
/etc/login.defs configuration file. In the default configuration UID_MIN is set
to 500, thus system accounts are those user accounts with a user ID less than
500. If any system account SYSACCT (other than root) has an unlocked password,
disable it with the command:
$ sudo passwd -l 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_shelllogin\_for\_systemaccounts
### Title: Ensure that System Accounts Do Not Run a Shell Upon Login
### Description:

```
Some accounts are not associated with a human user of the system, and exist to
perform some administrative function. Should an attacker be able to log into
these accounts, they should not be granted access to a shell.

The login shell for each local account is stored in the last field of each line
in /etc/passwd. System accounts are those user accounts with a user ID
less than UID_MIN, where value of UID_MIN directive is set in
/etc/login.defs configuration file. In the default configuration UID_MIN is set
to 1000, thus system accounts are those user accounts with a user ID less than
1000. The user ID is stored in the third field. If any system account
SYSACCT (other than root) has a login shell, disable it with the
command: $ sudo usermod -s /sbin/nologin 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_prevent\_direct\_root\_logins
### Title: Direct root Logins Are Not Allowed
### Description:

```
Configure the operating system to prevent direct logins to the
root account by performing the following operations:
$ sudo passwd -l root
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_restrict\_serial\_port\_logins
### Title: Restrict Serial Port Root Logins
### Description:

```
To restrict root logins on serial ports,
ensure lines of this form do not appear in /etc/securetty:
ttyS0
ttyS1
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_securetty\_root\_login\_console\_only
### Title: Restrict Virtual Console Root Logins
### Description:

```
To restrict root logins through the (deprecated) virtual console devices,
ensure lines of this form do not appear in /etc/securetty:
vc/1
vc/2
vc/3
vc/4
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_use\_pam\_wheel\_group\_for\_su
### Title: Enforce Usage of pam\_wheel with Group Parameter for su Authentication
### Description:

```
To ensure that only users who are members of the group set in the
group pam_wheel parameter can run commands with altered
privileges through the su command, make sure that the
following line exists in the file /etc/pam.d/su:
auth required pam_wheel.so use_uid group=
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_logon\_fail\_delay
### Title: Ensure the Logon Failure Delay is Set Correctly in login.defs
### Description:

```
To ensure the logon failure delay controlled by /etc/login.defs is set properly,
add or correct the FAIL_DELAY setting in /etc/login.defs to read as follows:
FAIL_DELAY 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_max\_concurrent\_login\_sessions
### Title: Limit the Number of Concurrent Login Sessions Allowed Per User
### Description:

```
Limiting the number of allowed users and sessions per user can limit risks related to Denial of
Service attacks. This addresses concurrent sessions for a single account and does not address
concurrent sessions by a single user via multiple accounts. To set the number of concurrent
sessions per user add the following line in /etc/security/limits.conf or
a file under /etc/security/limits.d/:
* hard maxlogins 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_polyinstantiated\_tmp
### Title: Configure Polyinstantiation of /tmp Directories
### Description:

```
To configure polyinstantiated /tmp directories, first create the parent directories
which will hold the polyinstantiation child directories. Use the following command:
$ sudo mkdir --mode 000 /tmp/tmp-inst
Then, add the following entry to /etc/security/namespace.conf:
/tmp     /tmp/tmp-inst/            level      root,adm
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_polyinstantiated\_var\_tmp
### Title: Configure Polyinstantiation of /var/tmp Directories
### Description:

```
To configure polyinstantiated /tmp directories, first create the parent directories
which will hold the polyinstantiation child directories. Use the following command:
$ sudo mkdir --mode 000 /var/tmp/tmp-inst
Then, add the following entry to /etc/security/namespace.conf:
/var/tmp /var/tmp/tmp-inst/    level      root,adm
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_tmout
### Title: Set Interactive Session Timeout
### Description:

```
Setting the TMOUT option in /etc/profile ensures that
all user sessions will terminate based on inactivity.
The value of TMOUT should be exported and read only.
The TMOUT

setting in a file loaded by /etc/profile, e.g.
/etc/profile.d/tmout.sh should read as follows:
TMOUT=
readonly TMOUT
export TMOUT
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_user\_dot\_group\_ownership
### Title: User Initialization Files Must Be Group-Owned By The Primary Group
### Description:

```
Change the group owner of interactive users files to the group found
in /etc/passwd for the user. To change the group owner of a local
interactive user home directory, use the following command:
$ sudo chgrp 

This rule ensures every initialization file related to an interactive user
is group-owned by an interactive user.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_user\_dot\_no\_world\_writable\_programs
### Title: User Initialization Files Must Not Run World-Writable Programs
### Description:

```
Set the mode on files being executed by the user initialization files with the
following command:
$ sudo chmod o-w 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_user\_dot\_user\_ownership
### Title: User Initialization Files Must Be Owned By the Primary User
### Description:

```
Set the owner of the user initialization files for interactive users to
the primary owner with the following command:
$ sudo chown 

This rule ensures every initialization file related to an interactive user
is owned by an interactive user.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_user\_interactive\_home\_directory\_exists
### Title: All Interactive Users Home Directories Must Exist
### Description:

```
Create home directories to all local interactive users that currently do not
have a home directory assigned. Use the following commands to create the user
home directory assigned in /etc/passwd:
$ sudo mkdir /home/
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownership\_home\_directories
### Title: All Interactive User Home Directories Must Be Group-Owned By The Primary Group
### Description:

```
Change the group owner of interactive users home directory to the
group found in /etc/passwd. To change the group owner of
interactive users home directory, use the following command:
$ sudo chgrp 

This rule ensures every home directory related to an interactive user is
group-owned by an interactive user. It also ensures that interactive users
are group-owners of one and only one home directory.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownership\_home\_directories
### Title: All Interactive User Home Directories Must Be Owned By The Primary User
### Description:

```
Change the owner of interactive users home directories to that correct
owner. To change the owner of a interactive users home directory, use
the following command:
$ sudo chown 

This rule ensures every home directory related to an interactive user is
owned by an interactive user. It also ensures that interactive users are
owners of one and only one home directory.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_home\_directories
### Title: All Interactive User Home Directories Must Have mode 0750 Or Less Permissive
### Description:

```
Change the mode of interactive users home directories to 0750. To
change the mode of interactive users home directory, use the
following command:
$ sudo chmod 0750 /home/
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_home\_dirs
### Title: Ensure that User Home Directories are not Group-Writable or World-Readable
### Description:

```
For each human user of the system, view the
permissions of the user's home directory:
# ls -ld /home/
Ensure that the directory is not group-writable and that it
is not world-readable. If necessary, repair the permissions:
# chmod g-w /home/
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_root\_path\_dirs\_no\_write
### Title: Ensure that Root's Path Does Not Include World or Group-Writable Directories
### Description:

```
For each element in root's path, run:
# ls -ld 
and ensure that write permissions are disabled for group and
other.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_root\_path\_no\_dot
### Title: Ensure that Root's Path Does Not Include Relative Paths or Null Directories
### Description:

```
Ensure that none of the directories in root's path is equal to a single
. character, or
that it contains any instances that lead to relative path traversal, such as
.. or beginning a path without the slash (/) character.
Also ensure that there are no "empty" elements in the path, such as in these examples:
PATH=:/bin
PATH=/bin:
PATH=/bin::/sbin
These empty elements have the same effect as a single . character.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_umask\_etc\_bashrc
### Title: Ensure the Default Bash Umask is Set Correctly
### Description:

```
To ensure the default umask for users of the Bash shell is set properly,
add or correct the umask setting in /etc/bashrc to read
as follows:
umask 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_umask\_etc\_login\_defs
### Title: Ensure the Default Umask is Set Correctly in login.defs
### Description:

```
To ensure the default umask controlled by /etc/login.defs is set properly,
add or correct the UMASK setting in /etc/login.defs to read as follows:
UMASK 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_umask\_etc\_profile
### Title: Ensure the Default Umask is Set Correctly in /etc/profile
### Description:

```
To ensure the default umask controlled by /etc/profile is set properly,
add or correct the umask setting in /etc/profile to read as follows:
umask 

Note that /etc/profile also reads scrips within /etc/profile.d directory.
These scripts are also valid files to set umask value. Therefore, they should also be
considered during the check and properly remediated, if necessary.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_umask\_interactive\_users
### Title: Ensure the Default Umask is Set Correctly For Interactive Users
### Description:

```
Remove the UMASK environment variable from all interactive users initialization files.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_apparmor\_installed
### Title: Ensure AppArmor is installed
### Description:

```
AppArmor provide Mandatory Access Controls.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_all\_apparmor\_profiles\_enforced
### Title: Enforce all AppArmor Profiles
### Description:

```
AppArmor profiles define what resources applications are able to access.
To set all profiles to enforce mode run the following command:
$ sudo aa-enforce /etc/apparmor.d/*
To list unconfined processes run the following command:

$ sudo apparmor_status | grep processes

Any unconfined processes may need to have a profile created or activated
for them and then be restarted.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_all\_apparmor\_profiles\_in\_enforce\_complain\_mode
### Title: All AppArmor Profiles are in enforce or complain mode
### Description:

```
AppArmor profiles define what resources applications are able to access.
To set all profiles to either enforce or complain  mode
run the following command to set all profiles to enforce mode:
$ sudo aa-enforce /etc/apparmor.d/*
run the following command to set all profiles to complain mode:
$ sudo aa-complain /etc/apparmor.d/*
To list unconfined processes run the following command:

$ sudo apparmor_status | grep processes

Any unconfined processes may need to have a profile created or activated
for them and then be restarted.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_apparmor\_configured
### Title: Ensure AppArmor is Active and Configured
### Description:

```
Verify that the Apparmor tool is configured to
control whitelisted applications and user home directory access
control.

The apparmor service can be enabled with the following command:
$ sudo systemctl enable apparmor.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_enable\_apparmor
### Title: Ensure AppArmor is enabled in the bootloader configuration
### Description:

```
Configure AppArmor to be enabled at boot time and verify that it has not been
overwritten by the bootloader boot parameters.

Note: This recommendation is designed around the grub bootloader, if LILO or
another bootloader is in use in your environment, enact equivalent settings.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_disable\_recovery
### Title: Disable Recovery Booting
### Description:

```
Ubuntu 22.04 systems support an "recovery boot" option that can be used
to prevent services from being started. The GRUB_DISABLE_RECOVERY
configuration option in /etc/default/grub should be set to
true to disable the generation of recovery mode menu entries. It is
also required to change the runtime configuration, run:
$ sudo update-grub 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_enable\_iommu\_force
### Title: IOMMU configuration directive
### Description:

```
On x86 architecture supporting VT-d, the IOMMU manages the access control policy between the hardware devices and some
    of the system critical units such as the memory.
To ensure that iommu=force is added as a kernel command line
argument to newly installed kernels, add iommu=force to the
default Grub2 command line for Linux operating systems. Modify the line within
/etc/default/grub as shown below:
GRUB_CMDLINE_LINUX="... iommu=force ..."
Run the following command to update command line for already installed kernels:# update-grub
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_l1tf\_argument
### Title: Configure L1 Terminal Fault mitigations
### Description:

```
L1 Terminal Fault (L1TF) is a hardware vulnerability which allows unprivileged
speculative access to data which is available in the Level 1 Data Cache when
the page table entry isn't present.

Select the appropriate mitigation by adding the argument
l1tf= to the default
GRUB 2 command line for the Linux operating system.
To ensure that l1tf= is added as a kernel command line
argument to newly installed kernels, add l1tf= to the
default Grub2 command line for Linux operating systems. Modify the line within
/etc/default/grub as shown below:
GRUB_CMDLINE_LINUX="... l1tf=
Run the following command to update command line for already installed kernels:# update-grub

Since Linux Kernel 4.19 you can check the L1TF vulnerability state with the
following command:
cat /sys/devices/system/cpu/vulnerabilities/l1tf
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_mce\_argument
### Title: Force kernel panic on uncorrected MCEs
### Description:

```
A Machine Check Exception is an error generated by the CPU itdetects an error
in itself, memory or I/O devices.
These errors may be corrected and generate a check log entry, if an error
cannot be corrected the kernel may panic or SIGBUS.

To force the kernel to panic on any uncorrected error reported by Machine Check
set the MCE tolerance to zero by adding mce=0
to the default GRUB 2 command line for the Linux operating system.
To ensure that mce=0 is added as a kernel command line
argument to newly installed kernels, add mce=0 to the
default Grub2 command line for Linux operating systems. Modify the line within
/etc/default/grub as shown below:
GRUB_CMDLINE_LINUX="... mce=0 ..."
Run the following command to update command line for already installed kernels:# update-grub
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_nosmap\_argument\_absent
### Title: Ensure SMAP is not disabled during boot
### Description:

```
The SMAP is used to prevent the supervisor mode from unintentionally reading/writing into
memory pages in the user space, it is enabled by default since Linux kernel 3.7.
But it could be disabled through kernel boot parameters.

Ensure that Supervisor Mode Access Prevention (SMAP) is not disabled by
the nosmap boot paramenter option.

Check that the line GRUB_CMDLINE_LINUX="..." within /etc/default/grub
doesn't contain the argument nosmap.
Run the following command to update command line for already installed kernels:
# grubby --update-kernel=ALL --remove-args="nosmap"
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_nosmep\_argument\_absent
### Title: Ensure SMEP is not disabled during boot
### Description:

```
The SMEP is used to prevent the supervisor mode from executing user space code,
it is enabled by default since Linux kernel 3.0. But it could be disabled through
kernel boot parameters.

Ensure that Supervisor Mode Execution Prevention (SMEP) is not disabled by
the nosmep boot paramenter option.

Check that the line GRUB_CMDLINE_LINUX="..." within /etc/default/grub
doesn't contain the argument nosmep.
Run the following command to update command line for already installed kernels:
# grubby --update-kernel=ALL --remove-args="nosmep"
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_rng\_core\_default\_quality\_argument
### Title: Configure the confidence in TPM for entropy
### Description:

```
The TPM security chip that is available in most modern systems has a hardware RNG.
It is also used to feed the entropy pool, but generally not credited entropy.

Use rng_core.default_quality in the kernel command line to set the trust
level on the hardware generators. The trust level defines the amount of entropy to credit.
A value of 0 tells the system not to trust the hardware random number generators
available, and doesn't credit any entropy to the pool.
A value of 1000 assigns full confidence in the generators, and credits all the
entropy it provides to the pool.

Note that the value of rng_core.default_quality is global, affecting the trust
on all hardware random number generators.

Select the appropriate confidence by adding the argument
rng_core.default_quality= to the default
GRUB 2 command line for the Linux operating system.
To ensure that rng_core.default_quality= is added as a kernel command line
argument to newly installed kernels, add rng_core.default_quality= to the
default Grub2 command line for Linux operating systems. Modify the line within
/etc/default/grub as shown below:
GRUB_CMDLINE_LINUX="... rng_core.default_quality=
Run the following command to update command line for already installed kernels:# update-grub
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_slab\_nomerge\_argument
### Title: Disable merging of slabs with similar size
### Description:

```
The kernel may merge similar slabs together to reduce overhead and increase
cache hotness of objects.
Disabling merging of slabs keeps the slabs separate and reduces the risk of
kernel heap overflows overwriting objects in merged caches.

To disable merging of slabs in the Kernel add the argument slab_nomerge=yes
to the default GRUB 2 command line for the Linux operating system.
To ensure that slab_nomerge=yes is added as a kernel command line
argument to newly installed kernels, add slab_nomerge=yes to the
default Grub2 command line for Linux operating systems. Modify the line within
/etc/default/grub as shown below:
GRUB_CMDLINE_LINUX="... slab_nomerge=yes ..."
Run the following command to update command line for already installed kernels:# update-grub
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_spec\_store\_bypass\_disable\_argument
### Title: Configure Speculative Store Bypass Mitigation
### Description:

```
Certain CPUs are vulnerable to an exploit against a common wide industry wide performance
optimization known as Speculative Store Bypass (SSB).

In such cases, recent stores to the same memory location cannot always be observed by later
loads during speculative execution. However, such stores are unlikely and thus they can be
detected prior to instruction retirement at the end of a particular speculation execution
window.

Since Linux Kernel 4.17 you can check the SSB mitigation state with the following command:
cat /sys/devices/system/cpu/vulnerabilities/spec_store_bypass

Select the appropriate SSB state by adding the argument
spec_store_bypass_disable= to the default
GRUB 2 command line for the Linux operating system.
To ensure that spec_store_bypass_disable= is added as a kernel command line
argument to newly installed kernels, add spec_store_bypass_disable= to the
default Grub2 command line for Linux operating systems. Modify the line within
/etc/default/grub as shown below:
GRUB_CMDLINE_LINUX="... spec_store_bypass_disable=
Run the following command to update command line for already installed kernels:# update-grub
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_spectre\_v2\_argument
### Title: Enforce Spectre v2 mitigation
### Description:

```
Spectre V2 is an indirect branch poisoning attack that can lead to data leakage.
An exploit for Spectre V2 tricks the indirect branch predictor into executing
code from a future indirect branch chosen by the attacker, even if the privilege
level is different.

Since Linux Kernel 4.15 you can check the Spectre V2 mitigation state with the following command:
cat /sys/devices/system/cpu/vulnerabilities/spectre_v2

Enforce the Spectre V2 mitigation by adding the argument
spectre_v2=on to the default
GRUB 2 command line for the Linux operating system.
To ensure that spectre_v2=on) is added as a kernel command line
argument to newly installed kernels, add spectre_v2=on) to the
default Grub2 command line for Linux operating systems. Modify the line within
/etc/default/grub as shown below:
GRUB_CMDLINE_LINUX="... spectre_v2=on) ..."
Run the following command to update command line for already installed kernels:# update-grub
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_systemd\_debug-shell\_argument\_absent
### Title: Ensure debug-shell service is not enabled during boot
### Description:

```
systemd's debug-shell service is intended to
diagnose systemd related boot issues with various systemctl
commands. Once enabled and following a system reboot, the root shell
will be available on tty9 which is access by pressing
CTRL-ALT-F9. The debug-shell service should only be used
for systemd related issues and should otherwise be disabled.

By default, the debug-shell systemd service is already disabled.

Ensure the debug-shell is not enabled by the systemd.debug-shel=1
boot paramenter option.

Check that the line GRUB_CMDLINE_LINUX="..." within /etc/default/grub
doesn't contain the argument systemd.debug-shell=1.
Run the following command to update command line for already installed kernels:
# grubby --update-kernel=ALL --remove-args="systemd.debug-shell"
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_grub2\_cfg
### Title: Verify /boot/grub/grub.cfg User Ownership
### Description:

```
The file /boot/grub/grub.cfg should
be owned by the root user to prevent destruction
or modification of the file.

To properly set the owner of /boot/grub/grub.cfg, run the command:
$ sudo chown root /boot/grub/grub.cfg 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_grub2\_cfg
### Title: Verify /boot/grub/grub.cfg Permissions
### Description:

```
File permissions for /boot/grub/grub.cfg should be set to 600.

To properly set the permissions of /boot/grub/grub.cfg, run the command:
$ sudo chmod 600 /boot/grub/grub.cfg
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_password
### Title: Set Boot Loader Password in grub2
### Description:

```
The grub2 boot loader should have a superuser account and password
protection enabled to protect boot-time settings.

Since plaintext passwords are a security risk, generate a hash for the password
by running the following command:

# grub2-mkpasswd-pbkdf2

When prompted, enter the password that was selected.


Using the hash from the output, modify the /etc/grub.d/40_custom
file with the following content:
set superusers="boot"
password_pbkdf2 boot grub.pbkdf2.sha512.VeryLongString

NOTE: the bootloader superuser account and password MUST differ from the
root account and password.
Once the superuser password has been added,
update the
grub.cfg file by running:
update-grub 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_uefi\_password
### Title: Set the UEFI Boot Loader Password
### Description:

```
The grub2 boot loader should have a superuser account and password
protection enabled to protect boot-time settings.

Since plaintext passwords are a security risk, generate a hash for the password
by running the following command:

# grub2-mkpasswd-pbkdf2

When prompted, enter the password that was selected.


Using the hash from the output, modify the /etc/grub.d/40_custom
file with the following content:
set superusers="boot"
password_pbkdf2 boot grub.pbkdf2.sha512.VeryLongString

NOTE: the bootloader superuser account and password MUST differ from the
root account and password.
Once the superuser password has been added,
update the
grub.cfg file by running:
update-grub 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_zipl\_audit\_argument
### Title: Enable Auditing to Start Prior to the Audit Daemon in zIPL
### Description:

```
To ensure all processes can be audited, even those which start prior to the audit daemon,
check that all boot entries in /boot/loader/entries/*.conf have audit=1
included in its options.

To ensure that new kernels and boot entries continue to enable audit,
add audit=1 to /etc/kernel/cmdline.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_zipl\_audit\_backlog\_limit\_argument
### Title: Extend Audit Backlog Limit for the Audit Daemon in zIPL
### Description:

```
To improve the kernel capacity to queue all log events, even those which start prior to the audit daemon,
check that all boot entries in /boot/loader/entries/*.conf have audit_backlog_limit=8192
included in its options.
To ensure that new kernels and boot entries continue to extend the audit log events queue,
add audit_backlog_limit=8192 to /etc/kernel/cmdline.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_disable\_entropy\_contribution\_for\_solid\_state\_drives
### Title: Ensure Solid State Drives Do Not Contribute To Random-Number Entropy Pool
### Description:

```
For each solid-state drive on the system, run:
 # echo 0 > /sys/block/DRIVE/queue/add_random
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_acpi\_custom\_method
### Title: Do not allow ACPI methods to be inserted/replaced at run time
### Description:

```
This debug facility allows ACPI AML methods to be inserted and/or replaced without rebooting
the system.
This configuration is available from kernel 3.0.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_ACPI_CUSTOM_METHOD, run the following command:
    grep CONFIG_ACPI_CUSTOM_METHOD /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_binfmt\_misc
### Title: Disable kernel support for MISC binaries
### Description:

```
Enabling CONFIG_BINFMT_MISC makes it possible to plug wrapper-driven binary formats
into the kernel. This is specially useful for programs that need an interpreter to run like
Java, Python and DOS emulators. Once you have registered such a binary class with the kernel,
you can start one of those programs simply by typing in its name at a shell prompt.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_BINFMT_MISC, run the following command:
    grep CONFIG_BINFMT_MISC /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_bug
### Title: Enable support for BUG()
### Description:

```
Disabling this option eliminates support for BUG and WARN, reducing the size of your kernel
image and potentially quietly ignoring numerous fatal conditions. You should only consider
disabling this option for embedded systems with no facilities for reporting errors.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_BUG, run the following command:
    grep CONFIG_BUG /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_compat\_brk
### Title: Disable compatibility with brk()
### Description:

```
Enabling compatiliby with brk() allows legacy binaries to run (i.e. those linked
against libc5). But this compatibility comes at the cost of not being able to randomize
the heap placement (ASLR).

Unless legacy binaries need to run on the system, set CONFIG_COMPAT_BRK to "n".

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_COMPAT_BRK, run the following command:
    grep CONFIG_COMPAT_BRK /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_compat\_vdso
### Title: Disable the 32-bit vDSO
### Description:

```
Certain buggy versions of glibc (2.3.3) will crash if they are presented with a 32-bit vDSO
that is not mapped at the address indicated in its segment table.
Setting CONFIG_COMPAT_VDSO to y turns off the 32-bit VDSO and works
aroud the glibc bug.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_COMPAT_VDSO, run the following command:
    grep CONFIG_COMPAT_VDSO /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_debug\_credentials
### Title: Enable checks on credential management
### Description:

```
Enable this to turn on some debug checking for credential management. The additional code keeps
track of the number of pointers from task_structs to any given cred struct, and checks to see
that this number never exceeds the usage count of the cred struct.

Furthermore, if SELinux is enabled, this also checks that the security pointer in the cred
struct is never seen to be invalid.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_DEBUG_CREDENTIALS, run the following command:
    grep CONFIG_DEBUG_CREDENTIALS /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_debug\_fs
### Title: Disable kernel debugfs
### Description:

```
debugfs is a virtual file system that kernel developers use to put debugging files
into. Enable this option to be able to read and write to these files.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_DEBUG_FS, run the following command:
    grep CONFIG_DEBUG_FS /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_debug\_list
### Title: Enable checks on linked list manipulation
### Description:

```
Enable this to turn on extended checks in the linked-list walking routines.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_DEBUG_LIST, run the following command:
    grep CONFIG_DEBUG_LIST /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_debug\_notifiers
### Title: Enable checks on notifier call chains
### Description:

```
Enable this to turn on sanity checking for notifier call chains. This is most useful for kernel
developers to make sure that modules properly unregister themselves from notifier chains.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_DEBUG_NOTIFIERS, run the following command:
    grep CONFIG_DEBUG_NOTIFIERS /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_debug\_sg
### Title: Enable checks on scatter-gather (SG) table operations
### Description:

```
Scatter-gather tables are mechanism used for high performance I/O on DMA devices.
Enable this to turn on checks on scatter-gather tables.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_DEBUG_SG, run the following command:
    grep CONFIG_DEBUG_SG /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_default\_mmap\_min\_addr
### Title: Configure low address space to protect from user allocation
### Description:

```
This is the portion of low virtual memory which should be protected from userspace allocation.
This configuration is available from kernel 3.14, but may be available if backported
by distros.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_DEFAULT_MMAP_MIN_ADDR, run the following command:
    grep CONFIG_DEFAULT_MMAP_MIN_ADDR /boot/config-*
    
    For each kernel installed, a line with value "65536" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_devkmem
### Title: Disable /dev/kmem virtual device support
### Description:

```
Disable support for the /dev/kmem device.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_DEVKMEM, run the following command:
    grep CONFIG_DEVKMEM /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_hibernation
### Title: Disable hibernation
### Description:

```
Enable the suspend to disk (STD) functionality, which is usually called "hibernation" in user
interfaces. STD checkpoints the system and powers it off; and restores that checkpoint on
reboot.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_HIBERNATION, run the following command:
    grep CONFIG_HIBERNATION /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_ia32\_emulation
### Title: Disable IA32 emulation
### Description:

```
Disables support for legacy 32-bit programs under a 64-bit kernel.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_IA32_EMULATION, run the following command:
    grep CONFIG_IA32_EMULATION /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_ipv6
### Title: Disable the IPv6 protocol
### Description:

```
Disable support for IP version 6 (IPv6).

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_IPV6, run the following command:
    grep CONFIG_IPV6 /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_kexec
### Title: Disable kexec system call
### Description:

```
kexec is a system call that implements the ability to shutdown your current kernel,
and to start another kernel. It is like a reboot but it is independent of the system firmware.
And like a reboot you can start any kernel with it, not just Linux.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_KEXEC, run the following command:
    grep CONFIG_KEXEC /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_legacy\_ptys
### Title: Disable legacy (BSD) PTY support
### Description:

```
Disable the Linux traditional BSD-like terminal names /dev/ptyxx for masters and /dev/ttyxx for
slaves of pseudo terminals, and use only the modern ptys (devpts) interface.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_LEGACY_PTYS, run the following command:
    grep CONFIG_LEGACY_PTYS /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_module\_sig
### Title: Enable module signature verification
### Description:

```
Check modules for valid signatures upon load.
Note that this option adds the OpenSSL development packages as a kernel build dependency so
that the signing tool can use its crypto library.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_MODULE_SIG, run the following command:
    grep CONFIG_MODULE_SIG /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_module\_sig\_all
### Title: Enable automatic signing of all modules
### Description:

```
Sign all modules during make modules_install. Without this option, modules must be signed
manually, using the scripts/sign-file tool.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_MODULE_SIG_ALL, run the following command:
    grep CONFIG_MODULE_SIG_ALL /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_module\_sig\_force
### Title: Require modules to be validly signed
### Description:

```
Reject unsigned modules or signed modules with an unknown key.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_MODULE_SIG_FORCE, run the following command:
    grep CONFIG_MODULE_SIG_FORCE /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_module\_sig\_hash
### Title: Specify the hash to use when signing modules
### Description:

```
This configures the kernel to build and sign modules using
 as the hash function.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_MODULE_SIG_HASH, run the following command:
    grep CONFIG_MODULE_SIG_HASH /boot/config-*
    
    For each kernel installed, a line with value "" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_module\_sig\_key
### Title: Specify module signing key to use
### Description:

```
Setting this option to something other than its default of certs/signing_key.pem will
disable the autogeneration of signing keys and allow the kernel modules to be signed with a key
of your choosing.

The string provided should identify a file containing both a private key and
its corresponding X.509 certificate in PEM form, or — on systems where the OpenSSL ENGINE_pkcs11
is functional — a PKCS#11 URI as defined by RFC7512. In the latter case, the PKCS#11 URI should
reference both a certificate and a private key.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_MODULE_SIG_KEY, run the following command:
    grep CONFIG_MODULE_SIG_KEY /boot/config-*
    
    For each kernel installed, a line with value "" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_module\_sig\_sha512
### Title: Sign kernel modules with SHA-512
### Description:

```
This configures the kernel to build and sign modules using SHA512 as the hash function.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_MODULE_SIG_SHA512, run the following command:
    grep CONFIG_MODULE_SIG_SHA512 /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_page\_poisoning\_no\_sanity
### Title: Enable poison without sanity check
### Description:

```
Skip the sanity checking on alloc, only fill the pages with poison on free. This reduces some
of the overhead of the poisoning feature.
This configuration is available from kernel 4.6.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_PAGE_POISONING_NO_SANITY, run the following command:
    grep CONFIG_PAGE_POISONING_NO_SANITY /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_page\_poisoning\_zero
### Title: Use zero for poisoning instead of debugging value
### Description:

```
Instead of using the existing poison value, fill the pages with zeros. This makes it harder to
detect when errors are occurring due to sanitization but the zeroing at free means that it is
no longer necessary to write zeros when GFP_ZERO is used on allocation.
This configuration is available from kernel 4.19.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_PAGE_POISONING_ZERO, run the following command:
    grep CONFIG_PAGE_POISONING_ZERO /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_page\_table\_isolation
### Title: Remove the kernel mapping in user mode
### Description:

```
This feature reduces the number of hardware side channels by ensuring that the majority of
kernel addresses are not mapped into userspace.
This configuration is available from kernel 4.15, but may be available if backported
by distros.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_PAGE_TABLE_ISOLATION, run the following command:
    grep CONFIG_PAGE_TABLE_ISOLATION /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_panic\_on\_oops
### Title: Kernel panic oops
### Description:

```
Enable the kernel to panic when it oopses.
This has the same effect as setting oops=panic on the kernel command line.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_PANIC_ON_OOPS, run the following command:
    grep CONFIG_PANIC_ON_OOPS /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_panic\_timeout
### Title: Kernel panic timeout
### Description:

```
Set the timeout value (in seconds) until a reboot occurs when the kernel panics.
A timeout of 0 configures the system to wait forever. With a timeout value greater than 0,
the system will wait the specified amount of seconds before rebooting. While a timeout value
less than 0 makes the system reboot immediately.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_PANIC_TIMEOUT, run the following command:
    grep CONFIG_PANIC_TIMEOUT /boot/config-*
    
    For each kernel installed, a line with value "" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_proc\_kcore
### Title: Disable support for /proc/kkcore
### Description:

```
Provides a virtual ELF core file of the live kernel.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_PROC_KCORE, run the following command:
    grep CONFIG_PROC_KCORE /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_randomize\_base
### Title: Randomize the address of the kernel image (KASLR)
### Description:

```
In support of Kernel Address Space Layout Randomization (KASLR), this randomizes the physical
address at which the kernel image is decompressed and the virtual address where the kernel
image is mapped.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_RANDOMIZE_BASE, run the following command:
    grep CONFIG_RANDOMIZE_BASE /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_randomize\_memory
### Title: Randomize the kernel memory sections
### Description:

```
Randomizes the base virtual address of kernel memory sections (physical memory mapping,
vmalloc & vmemmap).
This configuration is available from kernel 4.8, but may be available if backported
by distros.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_RANDOMIZE_MEMORY, run the following command:
    grep CONFIG_RANDOMIZE_MEMORY /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_retpoline
### Title: Avoid speculative indirect branches in kernel
### Description:

```
Compile kernel with the retpoline compiler options to guard against kernel-to-user data leaks
by avoiding speculative indirect branches.
Requires a compiler with -mindirect-branch=thunk-extern support for full protection.
The kernel may run slower.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_RETPOLINE, run the following command:
    grep CONFIG_RETPOLINE /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_seccomp
### Title: Enable seccomp to safely compute untrusted bytecode
### Description:

```
This kernel feature is useful for number crunching applications that may need to compute
untrusted bytecode during their execution. By using pipes or other transports made available
to the process as file descriptors supporting the read/write syscalls, it's possible to isolate
those applications in their own address space using seccomp.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_SECCOMP, run the following command:
    grep CONFIG_SECCOMP /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_seccomp\_filter
### Title: Enable use of Berkeley Packet Filter with seccomp
### Description:

```
Enable tasks to build secure computing environments defined in terms of Berkeley Packet Filter
programs which implement task-defined system call filtering polices.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_SECCOMP_FILTER, run the following command:
    grep CONFIG_SECCOMP_FILTER /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_security
### Title: Enable different security models
### Description:

```
This allows you to choose different security modules to be configured into your kernel.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_SECURITY, run the following command:
    grep CONFIG_SECURITY /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_security\_dmesg\_restrict
### Title: Restrict unprivileged access to the kernel syslog
### Description:

```
Enforce restrictions on unprivileged users reading the kernel syslog via dmesg(8).

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_SECURITY_DMESG_RESTRICT, run the following command:
    grep CONFIG_SECURITY_DMESG_RESTRICT /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_security\_writable\_hooks
### Title: Disable mutable hooks
### Description:

```
Ensure kernel structures associated with LSMs are always mapped as read-only after system boot.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_SECURITY_WRITABLE_HOOKS, run the following command:
    grep CONFIG_SECURITY_WRITABLE_HOOKS /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_security\_yama
### Title: Enable Yama support
### Description:

```
This enables support for LSM module Yama, which extends DAC support with additional system-wide
security settings beyond regular Linux discretionary access controls. The module will limit the
use of the system call ptrace().

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_SECURITY_YAMA, run the following command:
    grep CONFIG_SECURITY_YAMA /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_slub\_debug
### Title: Enable SLUB debugging support
### Description:

```
SLUB has extensive debug support features and this allows the allocator validation checking to
be enabled.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_SLUB_DEBUG, run the following command:
    grep CONFIG_SLUB_DEBUG /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_syn\_cookies
### Title: Enable TCP/IP syncookie support
### Description:

```
Normal TCP/IP networking is open to an attack known as SYN flooding.
It is denial-of-service attack that prevents legitimate remote users from being able to connect
to your computer during an ongoing attack.

When enabled the TCP/IP stack will use a cryptographic challenge protocol known as SYN cookies
to enable legitimate users to continue to connect, even when your machine is under attack.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_SYN_COOKIES, run the following command:
    grep CONFIG_SYN_COOKIES /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_unmap\_kernel\_at\_el0
### Title: Unmap kernel when running in userspace (aka KAISER)
### Description:

```
Speculation attacks against some high-performance processors can be used to bypass MMU
permission checks and leak kernel data to userspace. This can be defended against by unmapping
the kernel when running in userspace, mapping it back in on exception entry via a trampoline
page in the vector table.
This configuration is available from kernel 4.16, but may be available if backported
by distros.
The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_UNMAP_KERNEL_AT_EL0, run the following command:
    grep CONFIG_UNMAP_KERNEL_AT_EL0 /boot/config-*
    
    For each kernel installed, a line with value "y" should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_config\_x86\_vsyscall\_emulation
### Title: Disable x86 vsyscall emulation
### Description:

```
Disabling it is roughly equivalent to booting with vsyscall=none, except that it will also
disable the helpful warning if a program tries to use a vsyscall. With this option set to N,
offending programs will just segfault, citing addresses of the form 0xffffffffff600?00.
This configuration is available from kernel 3.19.

The configuration that was used to build kernel is available at /boot/config-*.
    To check the configuration value for CONFIG_X86_VSYSCALL_EMULATION, run the following command:
    grep CONFIG_X86_VSYSCALL_EMULATION /boot/config-*
    
    Configs with value 'n' are not explicitly set in the file, so either commented lines or no
    lines should be returned.
    
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_rsyslog\_installed
### Title: Ensure rsyslog is Installed
### Description:

```
Rsyslog is installed by default. The rsyslog package can be installed with the following command:  $ apt-get install rsyslog
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_rsyslog\_enabled
### Title: Enable rsyslog Service
### Description:

```
The rsyslog service provides syslog-style logging by default on Ubuntu 22.04.

The rsyslog service can be enabled with the following command:
$ sudo systemctl enable rsyslog.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ensure\_rtc\_utc\_configuration
### Title: Ensure real-time clock is set to UTC
### Description:

```
Ensure that the system real-time clock (RTC) is set to Coordinated Universal Time (UTC).
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_filecreatemode
### Title: Ensure rsyslog Default File Permissions Configured
### Description:

```
rsyslog will create logfiles that do not already exist on the system.
This settings controls what permissions will be applied to these newly
created files.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_encrypt\_offload\_actionsendstreamdriverauthmode
### Title: Ensure Rsyslog Authenticates Off-Loaded Audit Records
### Description:

```
Rsyslogd is a system utility providing support for message logging. Support
for both internet and UNIX domain sockets enables this utility to support both local
and remote logging.  Couple this utility with gnutls (which is a secure communications
library implementing the SSL, TLS and DTLS protocols), and you have a method to securely
encrypt and off-load auditing.

When using rsyslogd to off-load logs the remote system must be authenticated.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_encrypt\_offload\_actionsendstreamdrivermode
### Title: Ensure Rsyslog Encrypts Off-Loaded Audit Records
### Description:

```
Rsyslogd is a system utility providing support for message logging. Support
for both internet and UNIX domain sockets enables this utility to support both local
and remote logging.  Couple this utility with gnutls (which is a secure communications
library implementing the SSL, TLS and DTLS protocols), and you have a method to securely
encrypt and off-load auditing.

When using rsyslogd to off-load logs off a encrpytion system must be used.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_encrypt\_offload\_defaultnetstreamdriver
### Title: Ensure Rsyslog Encrypts Off-Loaded Audit Records
### Description:

```
Rsyslogd is a system utility providing support for message logging. Support
for both internet and UNIX domain sockets enables this utility to support both local
and remote logging.  Couple this utility with gnutls (which is a secure communications
library implementing the SSL, TLS and DTLS protocols), and you have a method to securely
encrypt and off-load auditing.

When using rsyslogd to off-load logs off an encryption system must be used.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_files\_groupownership
### Title: Ensure Log Files Are Owned By Appropriate Group
### Description:

```
The group-owner of all log files written by
rsyslog should be

adm.

These log files are determined by the second part of each Rule line in
/etc/rsyslog.conf and typically all appear in /var/log.
For each log file LOGFILE referenced in /etc/rsyslog.conf,
run the following command to inspect the file's group owner:
$ ls -l 
If the owner is not

adm,

run the following command to
correct this:

$ sudo chgrp adm 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_files\_ownership
### Title: Ensure Log Files Are Owned By Appropriate User
### Description:

```
The owner of all log files written by
rsyslog should be

syslog.

These log files are determined by the second part of each Rule line in
/etc/rsyslog.conf and typically all appear in /var/log.
For each log file LOGFILE referenced in /etc/rsyslog.conf,
run the following command to inspect the file's owner:
$ ls -l 
If the owner is not

syslog,

run the following command to
correct this:

$ sudo chown syslog 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_files\_permissions
### Title: Ensure System Log Files Have Correct Permissions
### Description:

```
The file permissions for all log files written by rsyslog should
be set to 640, or more restrictive. These log files are determined by the
second part of each Rule line in /etc/rsyslog.conf and typically
all appear in /var/log. For each log file LOGFILE
referenced in /etc/rsyslog.conf, run the following command to
inspect the file's permissions:
$ ls -l 
If the permissions are not 640 or more restrictive, run the following
command to correct this:
$ sudo chmod 640 "
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_remote\_access\_monitoring
### Title: Ensure remote access methods are monitored in Rsyslog
### Description:

```
Logging of remote access methods must be implemented to help identify cyber
attacks and ensure ongoing compliance with remote access policies are being
audited and upheld. An examples of a remote access method is the use of the
Remote Desktop Protocol (RDP) from an external, non-organization controlled
network. The /etc/rsyslog.conf or
/etc/rsyslog.d/*.conf file should contain a match for the following
selectors: auth.*, authpriv.*, and daemon.*. If
not, use the following as an example configuration:
auth.*;authpriv.*;daemon.*                              /var/log/secure
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_systemd-journal-remote\_installed
### Title: Install systemd-journal-remote Package
### Description:

```
Journald (via systemd-journal-remote ) supports the ability to send
log events it gathers to a remote log host or to receive messages
from remote hosts, thus enabling centralised log management.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_systemd-journald\_enabled
### Title: Enable systemd-journald Service
### Description:

```
The systemd-journald service is an essential component of
systemd.

The systemd-journald service can be enabled with the following command:
$ sudo systemctl enable systemd-journald.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dir\_groupowner\_system\_journal
### Title: Verify group-owner of system journal directories
### Description:

```
Verify the /run/log/journal and /var/log/journal directories are group-owned by
"systemd-journal" by using the following command:

$ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %G" {} \;

If any output returned is not owned by "systemd-journal", this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dir\_owner\_system\_journal
### Title: Verify owner of system journal directories
### Description:

```
Verify the /run/log/journal and /var/log/journal directories are owned by
"root" by using the following command:

$ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %U" {} \;

If any output returned is not owned by "root", this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dir\_permissions\_system\_journal
### Title: Verify Permissions on the system journal directories
### Description:

```
Verify the /run/log/journal and /var/log/journal directories have
permissions set to "2750" or less permissive by using the following command:

$ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %a" {} \;

If any output returned has a permission set greater than "2750", this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_journalctl
### Title: Verify Groupowner on the journalctl command
### Description:

```
Verify that the "journalctl" command is group-owned by "root" by
using the following command:

$ sudo find /usr/bin/journalctl -exec stat -c "%n %G" {} \;

If any output returned is not owned by "root", this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_system\_journal
### Title: Verify Group Who Owns the system journal
### Description:

```
Verify the /run/log/journal and /var/log/journal files are group-owned by
"systemd-journal" by using the following command:

$ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %G" {} \;

If any output returned is not group-owned by "systemd-journal", this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_journalctl
### Title: Verify Owner on the journalctl Command
### Description:

```
Verify that the "journalctl" command is owned by "root" by
using the following command:

$ sudo find /usr/bin/journalctl -exec stat -c "%n %U" {} \;

If any output returned is not owned by "root", this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_system\_journal
### Title: Verify Owner on the system journal
### Description:

```
Verify the /run/log/journal and /var/log/journal files are owned by
"root" by using the following command:

$ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %U" {} \;

If any output returned is not owned by "root", this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_journalctl
### Title: Verify Permissions on the journal command
### Description:

```
Verify that the "journalctl" command has a permission set of "740" by
using the following command:

 $ sudo find /usr/bin/journalctl -exec stat -c "%n %a" {} \;

If "journalctl" is not set to "740", this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_system\_journal
### Title: Verify Permissions on the system journal
### Description:

```
Verify all files in the /run/log/journal and /var/log/journal directories have
permissions set to "640" or less permissive by using the following command:

$ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %a" {} \;

If any output returned has a permission set greater than "640", this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_journald\_compress
### Title: Ensure journald is configured to compress large log files
### Description:

```
The journald system can compress large log files to avoid fill the system disk.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_journald\_storage
### Title: Ensure journald is configured to write log files to persistent disk
### Description:

```
The journald system may store log files in volatile memory or locally on disk.
If the logs are only stored in volatile memory they will we lost upon reboot.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_socket\_systemd-journal-remote\_disabled
### Title: Disable systemd-journal-remote Socket
### Description:

```
Journald supports the ability to receive messages from remote hosts,
thus acting as a log server. Clients should not receive data from
other hosts.
NOTE:
    The same package, systemd-journal-remote , is used for both sending
    logs to remote hosts and receiving incoming logs.
    With regards to receiving logs, there are two Systemd unit files;
    systemd-journal-remote.socket and systemd-journal-remote.service.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_logrotate\_installed
### Title: Ensure logrotate is Installed
### Description:

```
logrotate is installed by default. The logrotate package can be installed with the following command:  $ apt-get install logrotate
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ensure\_logrotate\_activated
### Title: Ensure Logrotate Runs Periodically
### Description:

```
The logrotate utility allows for the automatic rotation of
log files.  The frequency of rotation is specified in /etc/logrotate.conf,
which triggers a cron task or a timer.  To configure logrotate to run daily, add or correct
the following line in /etc/logrotate.conf:
# rotate log files 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_timer\_logrotate\_enabled
### Title: Enable logrotate Timer
### Description:

```
The logrotate timer can be enabled with the following command:
$ sudo systemctl enable logrotate.timer
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_syslogng\_installed
### Title: Ensure syslog-ng is Installed
### Description:

```
syslog-ng can be installed in replacement of rsyslog.
The syslog-ng-core package can be installed with the following command:

$ apt-get install syslog-ng-core
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_syslogng\_enabled
### Title: Enable syslog-ng Service
### Description:

```
The syslog-ng service (in replacement of rsyslog) provides syslog-style logging by default on Debian.

The syslog-ng service can be enabled with the following command:
$ sudo systemctl enable syslog-ng.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_accept\_remote\_messages\_tcp
### Title: Enable rsyslog to Accept Messages via TCP, if Acting As Log Server
### Description:

```
The rsyslog daemon should not accept remote messages
unless the system acts as a log server.
If the system needs to act as a central log server, add the following lines to
/etc/rsyslog.conf to enable reception of messages over TCP:
$ModLoad imtcp
$InputTCPServerRun 514
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_accept\_remote\_messages\_udp
### Title: Enable rsyslog to Accept Messages via UDP, if Acting As Log Server
### Description:

```
The rsyslog daemon should not accept remote messages
unless the system acts as a log server.
If the system needs to act as a central log server, add the following lines to
/etc/rsyslog.conf to enable reception of messages over UDP:
$ModLoad imudp
$UDPServerRun 514
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_nolisten
### Title: Ensure rsyslog Does Not Accept Remote Messages Unless Acting As Log Server
### Description:

```
The rsyslog daemon should not accept remote messages
unless the system acts as a log server.
To ensure that it is not listening on the network, ensure the following lines are
not found in /etc/rsyslog.conf:
$ModLoad imtcp
$InputTCPServerRun 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_remote\_loghost
### Title: Ensure Logs Sent To Remote Host
### Description:

```
To configure rsyslog to send logs to a remote log server,
open /etc/rsyslog.conf and read and understand the last section of the file,
which describes the multiple directives necessary to activate remote
logging.
Along with these other directives, the system can be configured
to forward its logs to a particular log server by
adding or correcting one of the following lines,
substituting  appropriately.
The choice of protocol depends on the environment of the system;
although TCP and RELP provide more reliable message delivery,
they may not be supported in all environments.

To use UDP for log message delivery:
*.* @

To use TCP for log message delivery:
*.* @@

To use RELP for log message delivery:
*.* :omrelp:

There must be a resolvable DNS CNAME or Alias record set to "" for logs to be sent correctly to the centralized logging utility.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_iptables-persistent\_installed
### Title: Install iptables-persistent Package
### Description:

```
The iptables-persistent package can be installed with the following command:

$ apt-get install iptables-persistent
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_iptables\_installed
### Title: Install iptables Package
### Description:

```
The iptables package can be installed with the following command:

$ apt-get install iptables
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_iptables-persistent\_removed
### Title: Remove iptables-persistent Package
### Description:

```
The iptables-persistent package can be removed with the following command:

$ apt-get remove iptables-persistent
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_ip6tables\_enabled
### Title: Verify ip6tables Enabled if Using IPv6
### Description:

```
The ip6tables service can be enabled with the following command:
$ sudo systemctl enable ip6tables.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_iptables\_enabled
### Title: Verify iptables Enabled
### Description:

```
The iptables service can be enabled with the following command:
$ sudo systemctl enable iptables.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_ip6tables\_default\_rule
### Title: Set Default ip6tables Policy for Incoming Packets
### Description:

```
To set the default policy to DROP (instead of ACCEPT) for
the built-in INPUT chain which processes incoming packets,
add or correct the following line in

/etc/iptables/rules.v6:

:INPUT DROP [0:0]
If changes were required, reload the ip6tables rules:
$ sudo service ip6tables reload
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_ipv6\_loopback\_traffic
### Title: Set configuration for IPv6 loopback traffic
### Description:

```
Configure the loopback interface to accept traffic.
Configure all other interfaces to deny traffic to the loopback
network.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_loopback\_traffic
### Title: Set configuration for loopback traffic
### Description:

```
Configure the loopback interface to accept traffic.
Configure all other interfaces to deny traffic to the loopback
network.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ip6tables\_rules\_for\_open\_ports
### Title: Ensure ip6tables Firewall Rules Exist for All Open Ports
### Description:

```
Any ports that have been opened on non-loopback addresses
need firewall rules to govern traffic.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_iptables\_rules\_for\_open\_ports
### Title: Ensure iptables Firewall Rules Exist for All Open Ports
### Description:

```
Any ports that have been opened on non-loopback addresses
need firewall rules to govern traffic.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_iptables\_default\_rule
### Title: Set Default iptables Policy for Incoming Packets
### Description:

```
To set the default policy to DROP (instead of ACCEPT) for
the built-in INPUT chain which processes incoming packets,
add or correct the following line in

/etc/iptables/rules.v4:

:INPUT DROP [0:0]
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_iptables\_default\_rule\_forward
### Title: Set Default iptables Policy for Forwarded Packets
### Description:

```
To set the default policy to DROP (instead of ACCEPT) for
the built-in FORWARD chain which processes packets that will be forwarded from
one interface to another,
add or correct the following line in
/etc/sysconfig/iptables:
:FORWARD DROP [0:0]
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_ipv6\_option\_disabled
### Title: Disable IPv6 Networking Support Automatic Loading
### Description:

```
To prevent the IPv6 kernel module (ipv6) from binding to the
IPv6 networking stack, add the following line to
/etc/modprobe.d/disabled.conf (or another file in
/etc/modprobe.d):
options ipv6 disable=1
This permits the IPv6 module to be loaded (and thus satisfy other modules that
depend on it), while disabling support for the IPv6 protocol.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv6\_conf\_all\_disable\_ipv6
### Title: Disable IPv6 Addressing on All IPv6 Interfaces
### Description:

```
To disable support for (ipv6) addressing on all interface add the following line to
/etc/sysctl.d/ipv6.conf (or another file in /etc/sysctl.d):
net.ipv6.conf.all.disable_ipv6 = 1
This disables IPv6 on all network interfaces as other services and system
functionality require the IPv6 stack loaded to work.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv6\_conf\_default\_disable\_ipv6
### Title: Disable IPv6 Addressing on IPv6 Interfaces by Default
### Description:

```
To disable support for (ipv6) addressing on interfaces by default add the following line to
/etc/sysctl.d/ipv6.conf (or another file in /etc/sysctl.d):
net.ipv6.conf.default.disable_ipv6 = 1
This disables IPv6 on network interfaces by default as other services and system
functionality require the IPv6 stack loaded to work.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv6\_conf\_all\_accept\_ra
### Title: Configure Accepting Router Advertisements on All IPv6 Interfaces
### Description:

```
To set the runtime status of the net.ipv6.conf.all.accept_ra kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.all.accept_ra=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.all.accept_ra = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv6\_conf\_all\_accept\_redirects
### Title: Disable Accepting ICMP Redirects for All IPv6 Interfaces
### Description:

```
To set the runtime status of the net.ipv6.conf.all.accept_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.all.accept_redirects = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv6\_conf\_all\_accept\_source\_route
### Title: Disable Kernel Parameter for Accepting Source-Routed Packets on all IPv6 Interfaces
### Description:

```
To set the runtime status of the net.ipv6.conf.all.accept_source_route kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.all.accept_source_route=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.all.accept_source_route = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv6\_conf\_all\_forwarding
### Title: Disable Kernel Parameter for IPv6 Forwarding
### Description:

```
To set the runtime status of the net.ipv6.conf.all.forwarding kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.all.forwarding=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.all.forwarding = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv6\_conf\_default\_accept\_ra
### Title: Disable Accepting Router Advertisements on all IPv6 Interfaces by Default
### Description:

```
To set the runtime status of the net.ipv6.conf.default.accept_ra kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.default.accept_ra=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.default.accept_ra = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv6\_conf\_default\_accept\_redirects
### Title: Disable Kernel Parameter for Accepting ICMP Redirects by Default on IPv6 Interfaces
### Description:

```
To set the runtime status of the net.ipv6.conf.default.accept_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.default.accept_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.default.accept_redirects = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv6\_conf\_default\_accept\_source\_route
### Title: Disable Kernel Parameter for Accepting Source-Routed Packets on IPv6 Interfaces by Default
### Description:

```
To set the runtime status of the net.ipv6.conf.default.accept_source_route kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.default.accept_source_route=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.default.accept_source_route = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_all\_accept\_local
### Title: Disable Accepting Packets Routed Between Local Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.accept_local kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.accept_local=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.accept_local = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_all\_accept\_redirects
### Title: Disable Accepting ICMP Redirects for All IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.accept_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.accept_redirects = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_all\_accept\_source\_route
### Title: Disable Kernel Parameter for Accepting Source-Routed Packets on all IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.accept_source_route kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.accept_source_route = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_all\_arp\_filter
### Title: Configure ARP filtering for All IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.arp_filter kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.arp_filter=
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.arp_filter = 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_all\_arp\_ignore
### Title: Configure Response Mode of ARP Requests for All IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.arp_ignore kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.arp_ignore=
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.arp_ignore = 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_all\_log\_martians
### Title: Enable Kernel Parameter to Log Martian Packets on all IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.log_martians kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.log_martians=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.log_martians = 1
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_all\_route\_localnet
### Title: Prevent Routing External Traffic to Local Loopback on All IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.route_localnet kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.route_localnet=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.route_localnet = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_all\_rp\_filter
### Title: Enable Kernel Parameter to Use Reverse Path Filtering on all IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.rp_filter kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.rp_filter=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.rp_filter = 1
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_all\_secure\_redirects
### Title: Disable Kernel Parameter for Accepting Secure ICMP Redirects on all IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.secure_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.secure_redirects = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_all\_shared\_media
### Title: Configure Sending and Accepting Shared Media Redirects for All IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.shared_media kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.shared_media=
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.shared_media = 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_default\_accept\_redirects
### Title: Disable Kernel Parameter for Accepting ICMP Redirects by Default on IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.default.accept_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.accept_redirects = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_default\_accept\_source\_route
### Title: Disable Kernel Parameter for Accepting Source-Routed Packets on IPv4 Interfaces by Default
### Description:

```
To set the runtime status of the net.ipv4.conf.default.accept_source_route kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.accept_source_route=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.accept_source_route = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_default\_log\_martians
### Title: Enable Kernel Paremeter to Log Martian Packets on all IPv4 Interfaces by Default
### Description:

```
To set the runtime status of the net.ipv4.conf.default.log_martians kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.log_martians=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.log_martians = 1
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_default\_rp\_filter
### Title: Enable Kernel Parameter to Use Reverse Path Filtering on all IPv4 Interfaces by Default
### Description:

```
To set the runtime status of the net.ipv4.conf.default.rp_filter kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.rp_filter=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.rp_filter = 1
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_default\_secure\_redirects
### Title: Configure Kernel Parameter for Accepting Secure Redirects By Default
### Description:

```
To set the runtime status of the net.ipv4.conf.default.secure_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.secure_redirects = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_default\_shared\_media
### Title: Configure Sending and Accepting Shared Media Redirects by Default
### Description:

```
To set the runtime status of the net.ipv4.conf.default.shared_media kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.shared_media=
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.shared_media = 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_icmp\_echo\_ignore\_broadcasts
### Title: Enable Kernel Parameter to Ignore ICMP Broadcast Echo Requests on IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.icmp_echo_ignore_broadcasts kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.icmp_echo_ignore_broadcasts = 1
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_icmp\_ignore\_bogus\_error\_responses
### Title: Enable Kernel Parameter to Ignore Bogus ICMP Error Responses on IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.icmp_ignore_bogus_error_responses kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.icmp_ignore_bogus_error_responses = 1
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_tcp\_syncookies
### Title: Enable Kernel Parameter to Use TCP Syncookies on Network Interfaces
### Description:

```
To set the runtime status of the net.ipv4.tcp_syncookies kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.tcp_syncookies=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.tcp_syncookies = 1
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_all\_send\_redirects
### Title: Disable Kernel Parameter for Sending ICMP Redirects on all IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.send_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.send_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.send_redirects = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_default\_send\_redirects
### Title: Disable Kernel Parameter for Sending ICMP Redirects on all IPv4 Interfaces by Default
### Description:

```
To set the runtime status of the net.ipv4.conf.default.send_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.send_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.send_redirects = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_ip\_forward
### Title: Disable Kernel Parameter for IP Forwarding on IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.ip_forward kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.ip_forward=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.ip_forward = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_nftables\_installed
### Title: Install nftables Package
### Description:

```
nftables provides a new in-kernel packet classification framework that is based on a
network-specific Virtual Machine (VM) and a new nft userspace command line tool.
nftables reuses the existing Netfilter subsystems such as the existing hook infrastructure,
the connection tracking system, NAT, userspace queuing and logging subsystem.
The nftables package can be installed with the following command:

$ apt-get install nftables
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_nftables\_removed
### Title: Uninstall nftables package
### Description:

```
nftables is a subsystem of the Linux kernel providing filtering and classification of network
packets/datagrams/frames and is the successor to iptables.
The nftables package can be removed with the following command:

$ apt-get remove nftables
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_nftables\_enabled
### Title: Verify nftables Service is Enabled
### Description:

```
The nftables service allows for the loading of nftables rulesets during boot,
or starting on the nftables service

The nftables service can be enabled with the following command:
$ sudo systemctl enable nftables.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_nftables\_disabled
### Title: Verify nftables service disabled
### Description:

```
nftables is a subsystem of the Linux kernel providing filtering and classification of network
packets/datagrams/frames and is the successor to iptables.
The nftables package can be removed with the following command:

$ apt-get remove nftables
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_nftables\_ensure\_default\_deny\_policy
### Title: Ensure nftables default deny firewall policy
### Description:

```
Base chain policy is the default verdict that will be applied to packets reaching the end of
the chain.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_nftables\_rules\_permanent
### Title: Ensure nftables rules are permanent
### Description:

```
nftables is a subsystem of the Linux kernel providing filtering and classification of
network packets/datagrams/frames. The nftables service reads the
 file for a nftables file or files to
include in the nftables ruleset. A nftables ruleset containing the input, forward, and output
base chains allow network traffic to be filtered.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_nftables\_base\_chain
### Title: Ensure Base Chains Exist for Nftables
### Description:

```
Tables in nftables hold chains. Each table only has one address family and only applies
to packets of this family. Tables can have one of six families.
Chains are containers for rules. They exist in two kinds, base chains and regular chains.
A base chain is an entry point for packets from the networking stack, a regular chain may
be used as jump target and is used for better rule organization.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_nftables\_loopback\_traffic
### Title: Set nftables configuration for loopback traffic
### Description:

```
Configure the loopback interface to accept traffic.
Configure all other interfaces to deny traffic to the loopback
network.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_nftables\_table
### Title: Ensure a Table Exists for Nftables
### Description:

```
Tables in nftables hold chains. Each table only has one address family and only applies
to packets of this family. Tables can have one of six families.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_ufw\_installed
### Title: Install ufw Package
### Description:

```
The ufw package can be installed with the following command:

$ apt-get install ufw
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_ufw\_removed
### Title: Remove ufw Package
### Description:

```
The ufw package can be removed with the following command:

$ apt-get remove ufw
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_ufw\_enabled
### Title: Verify ufw Enabled
### Description:

```
The ufw service can be enabled with the following command:
$ sudo systemctl enable ufw.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_check\_ufw\_active
### Title: Verify ufw Active
### Description:

```
Verify the ufw is enabled on the system with the following command:
# sudo ufw status
If the above command returns the status as "inactive" or any type of error, this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_ufw\_default\_rule
### Title: Ensure ufw Default Deny Firewall Policy
### Description:

```
A default deny policy on connections ensures that any unconfigured
network usage will be rejected.

Note: Any port or protocol without a explicit allow before the default
deny will be blocked.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_ufw\_loopback\_traffic
### Title: Set UFW Loopback Traffic
### Description:

```
Configure the loopback interface to accept traffic.
Configure all other interfaces to deny traffic to the loopback
network.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ufw\_only\_required\_services
### Title: Only Allow Authorized Network Services in ufw
### Description:

```
Check the firewall configuration for any unnecessary or prohibited
functions, ports, protocols, and/or services by running the following
command:
$ sudo ufw show raw
Chain OUTPUT (policy ACCEPT)
target prot opt sources destination
Chain INPUT (policy ACCEPT 1 packets, 40 bytes)
pkts bytes target prot opt in out source destination
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
pkts bytes target prot opt in out source destination
Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
pkts bytes target prot opt in out source destination

Ask the System Administrator for the site or program PPSM CLSA. Verify
the services allowed by the firewall match the PPSM CLSA.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ufw\_rate\_limit
### Title: ufw Must rate-limit network interfaces
### Description:

```
The operating system must configure the uncomplicated firewall to
rate-limit impacted network interfaces.

Check all the services listening to the ports with the following
command:
$ sudo ss -l46ut
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp LISTEN 0 128 [::]:ssh [::]:*

For each entry, verify that the ufw is configured to rate limit the
service ports with the following command:
$ sudo ufw status

If any port with a state of "LISTEN" is not marked with the "LIMIT"
action, run the following command, replacing "service" with the
service that needs to be rate limited:
$ sudo ufw limit "service"

Rate-limiting can also be done on an interface. An example of adding
a rate-limit on the eth0 interface follows:
$ sudo ufw limit in on eth0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ufw\_rules\_for\_open\_ports
### Title: Ensure ufw Firewall Rules Exist for All Open Ports
### Description:

```
Any ports that have been opened on non-loopback addresses
need firewall rules to govern traffic.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_dccp\_disabled
### Title: Disable DCCP Support
### Description:

```
The Datagram Congestion Control Protocol (DCCP) is a
relatively new transport layer protocol, designed to support
streaming media and telephony.

To configure the system to prevent the dccp
kernel module from being loaded, add the following line to the file /etc/modprobe.d/dccp.conf:
install dccp /bin/false
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_rds\_disabled
### Title: Disable RDS Support
### Description:

```
The Reliable Datagram Sockets (RDS) protocol is a transport
layer protocol designed to provide reliable high-bandwidth,
low-latency communications between nodes in a cluster.

To configure the system to prevent the rds
kernel module from being loaded, add the following line to the file /etc/modprobe.d/rds.conf:
install rds /bin/false
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_sctp\_disabled
### Title: Disable SCTP Support
### Description:

```
The Stream Control Transmission Protocol (SCTP) is a
transport layer protocol, designed to support the idea of
message-oriented communication, with several streams of messages
within one connection.

To configure the system to prevent the sctp
kernel module from being loaded, add the following line to the file /etc/modprobe.d/sctp.conf:
install sctp /bin/false
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_tipc\_disabled
### Title: Disable TIPC Support
### Description:

```
The Transparent Inter-Process Communication (TIPC) protocol
is designed to provide communications between nodes in a
cluster.

To configure the system to prevent the tipc
kernel module from being loaded, add the following line to the file /etc/modprobe.d/tipc.conf:
install tipc /bin/false
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_wireless\_disable\_interfaces
### Title: Deactivate Wireless Network Interfaces
### Description:

```
Deactivating wireless network interfaces should prevent normal usage of the wireless
capability.


Verify that there are no wireless interfaces configured on the system
with the following command:
$ ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename -a
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_only\_allow\_dod\_certs
### Title: Only Allow DoD PKI-established CAs
### Description:

```
The operating system must only allow the use of DoD PKI-established
certificate authorities for verification of the establishment of
protected sessions.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dir\_perms\_world\_writable\_sticky\_bits
### Title: Verify that All World-Writable Directories Have Sticky Bits Set
### Description:

```
When the so-called 'sticky bit' is set on a directory,
only the owner of a given file may remove that file from the
directory. Without the sticky bit, any user with write access to a
directory may remove any file in the directory. Setting the sticky
bit prevents users from removing each other's files. In cases where
there is no reason for a directory to be world-writable, a better
solution is to remove that permission rather than to set the sticky
bit. However, if a directory is used by a particular application,
consult that application's documentation instead of blindly
changing modes.

To set the sticky bit on a world-writable directory DIR, run the
following command:
$ sudo chmod +t 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_audit\_auditd
### Title: Verify Permissions on /etc/audit/auditd.conf
### Description:

```
To properly set the permissions of /etc/audit/auditd.conf, run the command:
$ sudo chmod 0640 /etc/audit/auditd.conf
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_audit\_rules
### Title: Verify Permissions on /etc/audit/audit.rules
### Description:

```
To properly set the permissions of /etc/audit/audit.rules, run the command:
$ sudo chmod 0640 /etc/audit/audit.rules
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_audit\_rulesd
### Title: Verify Permissions on /etc/audit/rules.d/\*.rules
### Description:

```
To properly set the permissions of /etc/audit/rules.d/*.rules, run the command:
$ sudo chmod 0640 /etc/audit/rules.d/*.rules
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_systemmap
### Title: Verify that local System.map file (if exists) is readable only by root
### Description:

```
Files containing sensitive informations should be protected by restrictive
  permissions. Most of the time, there is no need that these files need to be read by any non-root user

To properly set the permissions of /boot/System.map-*, run the command:
$ sudo chmod 0600 /boot/System.map-*
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_unauthorized\_world\_writable
### Title: Ensure No World-Writable Files Exist
### Description:

```
It is generally a good idea to remove global (other) write
access to a file when it is discovered. However, check with
documentation for specific applications before making changes.
Also, monitor for recurring world-writable files, as these may be
symptoms of a misconfigured application or user account. Finally,
this applies to real files and not virtual files that are a part of
pseudo file systems such as sysfs or procfs.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_ungroupowned
### Title: Ensure All Files Are Owned by a Group
### Description:

```
If any files are not owned by a group, then the
cause of their lack of group-ownership should be investigated.
Following this, the files should be deleted or assigned to an
appropriate group. The following command will discover and print
any files on local partitions which do not belong to a valid group:
$ df --local -P | awk '{if (NR!=1) print $6}' | sudo xargs -I '{}' find '{}' -xdev -nogroup
To search all filesystems on a system including network mounted
filesystems the following command can be run manually for each partition:
$ sudo find PARTITION -xdev -nogroup
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_files\_unowned\_by\_user
### Title: Ensure All Files Are Owned by a User
### Description:

```
If any files are not owned by a user, then the
cause of their lack of ownership should be investigated.
Following this, the files should be deleted or assigned to an
appropriate user. The following command will discover and print
any files on local partitions which do not belong to a valid user:
$ df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nouser
To search all filesystems on a system including network mounted
filesystems the following command can be run manually for each partition:
$ sudo find PARTITION -xdev -nouser
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_permissions\_local\_var\_log
### Title: Verify permissions of log files
### Description:

```
Any operating system providing too much information in error messages
risks compromising the data and security of the structure, and content
of error messages needs to be carefully considered by the organization.

Organizations carefully consider the structure/content of error messages.
The extent to which information systems are able to identify and handle
error conditions is guided by organizational policy and operational
requirements. Information that could be exploited by adversaries includes,
for example, erroneous logon attempts with passwords entered by mistake
as the username, mission/business information that can be derived from
(if not stated explicitly by) information recorded, and personal
information, such as account numbers, social security numbers, and credit
card numbers.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_fs\_protected\_hardlinks
### Title: Enable Kernel Parameter to Enforce DAC on Hardlinks
### Description:

```
To set the runtime status of the fs.protected_hardlinks kernel parameter, run the following command: $ sudo sysctl -w fs.protected_hardlinks=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: fs.protected_hardlinks = 1
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_fs\_protected\_symlinks
### Title: Enable Kernel Parameter to Enforce DAC on Symlinks
### Description:

```
To set the runtime status of the fs.protected_symlinks kernel parameter, run the following command: $ sudo sysctl -w fs.protected_symlinks=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: fs.protected_symlinks = 1
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_backup\_etc\_group
### Title: Verify Group Who Owns Backup group File
### Description:

```
 To properly set the group owner of /etc/group-, run the command: $ sudo chgrp root /etc/group-
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_backup\_etc\_gshadow
### Title: Verify Group Who Owns Backup gshadow File
### Description:

```
 To properly set the group owner of /etc/gshadow-, run the command: $ sudo chgrp shadow /etc/gshadow-
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_backup\_etc\_passwd
### Title: Verify Group Who Owns Backup passwd File
### Description:

```
 To properly set the group owner of /etc/passwd-, run the command: $ sudo chgrp root /etc/passwd-
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_backup\_etc\_shadow
### Title: Verify User Who Owns Backup shadow File
### Description:

```
 To properly set the group owner of /etc/shadow-, run the command: $ sudo chgrp shadow /etc/shadow-
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_group
### Title: Verify Group Who Owns group File
### Description:

```
 To properly set the group owner of /etc/group, run the command: $ sudo chgrp root /etc/group
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_gshadow
### Title: Verify Group Who Owns gshadow File
### Description:

```
 To properly set the group owner of /etc/gshadow, run the command: $ sudo chgrp shadow /etc/gshadow
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_passwd
### Title: Verify Group Who Owns passwd File
### Description:

```
 To properly set the group owner of /etc/passwd, run the command: $ sudo chgrp root /etc/passwd
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_shadow
### Title: Verify Group Who Owns shadow File
### Description:

```
 To properly set the group owner of /etc/shadow, run the command: $ sudo chgrp shadow /etc/shadow
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_backup\_etc\_group
### Title: Verify User Who Owns Backup group File
### Description:

```
 To properly set the owner of /etc/group-, run the command: $ sudo chown root /etc/group- 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_backup\_etc\_gshadow
### Title: Verify User Who Owns Backup gshadow File
### Description:

```
 To properly set the owner of /etc/gshadow-, run the command: $ sudo chown root /etc/gshadow- 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_backup\_etc\_passwd
### Title: Verify User Who Owns Backup passwd File
### Description:

```
 To properly set the owner of /etc/passwd-, run the command: $ sudo chown root /etc/passwd- 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_backup\_etc\_shadow
### Title: Verify Group Who Owns Backup shadow File
### Description:

```
 To properly set the owner of /etc/shadow-, run the command: $ sudo chown root /etc/shadow- 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_group
### Title: Verify User Who Owns group File
### Description:

```
 To properly set the owner of /etc/group, run the command: $ sudo chown root /etc/group 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_gshadow
### Title: Verify User Who Owns gshadow File
### Description:

```
 To properly set the owner of /etc/gshadow, run the command: $ sudo chown root /etc/gshadow 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_passwd
### Title: Verify User Who Owns passwd File
### Description:

```
 To properly set the owner of /etc/passwd, run the command: $ sudo chown root /etc/passwd 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_shadow
### Title: Verify User Who Owns shadow File
### Description:

```
 To properly set the owner of /etc/shadow, run the command: $ sudo chown root /etc/shadow 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_backup\_etc\_group
### Title: Verify Permissions on Backup group File
### Description:

```
To properly set the permissions of /etc/group-, run the command:
$ sudo chmod 0644 /etc/group-
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_backup\_etc\_gshadow
### Title: Verify Permissions on Backup gshadow File
### Description:

```
To properly set the permissions of /etc/gshadow-, run the command:
$ sudo chmod 0640 /etc/gshadow-
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_backup\_etc\_passwd
### Title: Verify Permissions on Backup passwd File
### Description:

```
To properly set the permissions of /etc/passwd-, run the command:
$ sudo chmod 0644 /etc/passwd-
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_backup\_etc\_shadow
### Title: Verify Permissions on Backup shadow File
### Description:

```
To properly set the permissions of /etc/shadow-, run the command:
$ sudo chmod 0640 /etc/shadow-
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_group
### Title: Verify Permissions on group File
### Description:

```
To properly set the permissions of /etc/passwd, run the command:
$ sudo chmod 0644 /etc/passwd
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_gshadow
### Title: Verify Permissions on gshadow File
### Description:

```
To properly set the permissions of /etc/gshadow, run the command:
$ sudo chmod 0640 /etc/gshadow
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_passwd
### Title: Verify Permissions on passwd File
### Description:

```
To properly set the permissions of /etc/passwd, run the command:
$ sudo chmod 0644 /etc/passwd
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_shadow
### Title: Verify Permissions on shadow File
### Description:

```
To properly set the permissions of /etc/shadow, run the command:
$ sudo chmod 0640 /etc/shadow
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log
### Title: Verify Group Who Owns /var/log Directory
### Description:

```
 To properly set the group owner of /var/log, run the command: $ sudo chgrp syslog /var/log
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log\_messages
### Title: Verify Group Who Owns /var/log/messages File
### Description:

```
 To properly set the group owner of /var/log/messages, run the command: $ sudo chgrp root /var/log/messages
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log\_syslog
### Title: Verify Group Who Owns /var/log/syslog File
### Description:

```
 To properly set the group owner of /var/log/syslog, run the command: $ sudo chgrp adm /var/log/syslog
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log
### Title: Verify User Who Owns /var/log Directory
### Description:

```
 To properly set the owner of /var/log, run the command: $ sudo chown root /var/log 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log\_messages
### Title: Verify User Who Owns /var/log/messages File
### Description:

```
 To properly set the owner of /var/log/messages, run the command: $ sudo chown root /var/log/messages 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log\_syslog
### Title: Verify User Who Owns /var/log/syslog File
### Description:

```
 To properly set the owner of /var/log/syslog, run the command: $ sudo chown syslog /var/log/syslog 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log
### Title: Verify Permissions on /var/log Directory
### Description:

```
To properly set the permissions of /var/log, run the command:
$ sudo chmod 0755 /var/log
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_messages
### Title: Verify Permissions on /var/log/messages File
### Description:

```
To properly set the permissions of /var/log/messages, run the command:
$ sudo chmod 0640 /var/log/messages
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_syslog
### Title: Verify Permissions on /var/log/syslog File
### Description:

```
To properly set the permissions of /var/log/syslog, run the command:
$ sudo chmod 0640 /var/log/syslog
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dir\_group\_ownership\_library\_dirs
### Title: Verify that Shared Library Directories Have Root Group Ownership
### Description:

```
System-wide shared library files, which are linked to executables
during process load time or run time, are stored in the following directories
by default:
/lib
/lib64
/usr/lib
/usr/lib64

Kernel modules, which can be added to the kernel during runtime, are also
stored in /lib/modules. All files in these directories should be
group-owned by the root user. If the  directories, is found to be owned
by a user other than root correct its
ownership with the following command:
$ sudo chgrp root 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dir\_groupownership\_binary\_dirs
### Title: Verify that system commands directories are group owned by root
### Description:

```
System commands files are stored in the following directories by default:
/bin
/sbin
/usr/bin
/usr/sbin
/usr/local/bin
/usr/local/sbin

All these directories should be owned by the root group.
If the directory is found to be owned by a group other than root correct
its ownership with the following command:
$ sudo chgrp root 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dir\_ownership\_binary\_dirs
### Title: Verify that System Executable Have Root Ownership
### Description:

```
/bin
/sbin
/usr/bin
/usr/sbin
/usr/local/bin
/usr/local/sbin
All these directories should be owned by the root user.
If any directory DIR in these directories is found
to be owned by a user other than root, correct its ownership with the
following command:
$ sudo chown root 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dir\_ownership\_library\_dirs
### Title: Verify that Shared Library Directories Have Root Ownership
### Description:

```
System-wide shared library files, which are linked to executables
during process load time or run time, are stored in the following directories
by default:
/lib
/lib64
/usr/lib
/usr/lib64

Kernel modules, which can be added to the kernel during runtime, are also
stored in /lib/modules. All files in these directories should be
owned by the root user. If the  directories, is found to be owned
by a user other than root correct its
ownership with the following command:
$ sudo chown root 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dir\_permissions\_binary\_dirs
### Title: Verify that System Executable Directories Have Restrictive Permissions
### Description:

```
System executables are stored in the following directories by default:
/bin
/sbin
/usr/bin
/usr/sbin
/usr/local/bin
/usr/local/sbin
These directories should not be group-writable or world-writable.
If any directory DIR in these directories is found to be
group-writable or world-writable, correct its permission with the
following command:
$ sudo chmod go-w 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dir\_permissions\_library\_dirs
### Title: Verify that Shared Library Directories Have Restrictive Permissions
### Description:

```
System-wide shared library directories, which contain are linked to executables
during process load time or run time, are stored in the following directories
by default:
/lib
/lib64
/usr/lib
/usr/lib64

Kernel modules, which can be added to the kernel during runtime, are
stored in /lib/modules. All sub-directories in these directories
should not be group-writable or world-writable. If any file in these
directories is found to be group-writable or world-writable, correct
its permission with the following command:
$ sudo chmod go-w 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownership\_audit\_binaries
### Title: Verify that audit tools are owned by group root
### Description:

```
The Ubuntu 22.04 operating system audit tools must have the proper
ownership configured to protected against unauthorized access.

Verify it by running the following command:
$ stat -c "%n %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd /sbin/augenrules

/sbin/auditctl root
/sbin/aureport root
/sbin/ausearch root
/sbin/autrace root
/sbin/auditd root
/sbin/audispd root
/sbin/augenrules root


Audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownership\_system\_commands\_dirs
### Title: Verify that system commands files are group owned by root or a system account
### Description:

```
System commands files are stored in the following directories by default:
/bin
/sbin
/usr/bin
/usr/sbin
/usr/local/bin
/usr/local/sbin

All files in these directories should be owned by the root group,
or a system account.
If the directory, or any file in these directories, is found to be owned
by a group other than root or a a system account correct its ownership
with the following command:
$ sudo chgrp root 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownership\_audit\_binaries
### Title: Verify that audit tools are owned by root
### Description:

```
The Ubuntu 22.04 operating system audit tools must have the proper
ownership configured to protected against unauthorized access.

Verify it by running the following command:
$ stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd /sbin/augenrules

/sbin/auditctl root
/sbin/aureport root
/sbin/ausearch root
/sbin/autrace root
/sbin/auditd root
/sbin/audispd root
/sbin/augenrules root


Audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownership\_binary\_dirs
### Title: Verify that System Executables Have Root Ownership
### Description:

```
System executables are stored in the following directories by default:
/bin
/sbin
/usr/bin
/usr/libexec
/usr/local/bin
/usr/local/sbin
/usr/sbin
All files in these directories should be owned by the root user.
If any file FILE in these directories is found
to be owned by a user other than root, correct its ownership with the
following command:
$ sudo chown root 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownership\_library\_dirs
### Title: Verify that Shared Library Files Have Root Ownership
### Description:

```
System-wide shared library files, which are linked to executables
during process load time or run time, are stored in the following directories
by default:
/lib
/lib64
/usr/lib
/usr/lib64

Kernel modules, which can be added to the kernel during runtime, are also
stored in /lib/modules. All files in these directories should be
owned by the root user. If the directory, or any file in these
directories, is found to be owned by a user other than root correct its
ownership with the following command:
$ sudo chown root 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_audit\_binaries
### Title: Verify that audit tools Have Mode 0755 or less
### Description:

```
The Ubuntu 22.04 operating system audit tools must have the proper
permissions configured to protected against unauthorized access.

Verify it by running the following command:
$ stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd /sbin/augenrules

/sbin/auditctl 755
/sbin/aureport 755
/sbin/ausearch 755
/sbin/autrace 755
/sbin/auditd 755
/sbin/audispd 755
/sbin/augenrules 755


Audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_binary\_dirs
### Title: Verify that System Executables Have Restrictive Permissions
### Description:

```
System executables are stored in the following directories by default:
/bin
/sbin
/usr/bin
/usr/libexec
/usr/local/bin
/usr/local/sbin
/usr/sbin
All files in these directories should not be group-writable or world-writable.
If any file FILE in these directories is found
to be group-writable or world-writable, correct its permission with the
following command:
$ sudo chmod go-w 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_library\_dirs
### Title: Verify that Shared Library Files Have Restrictive Permissions
### Description:

```
System-wide shared library files, which are linked to executables
during process load time or run time, are stored in the following directories
by default:
/lib
/lib64
/usr/lib
/usr/lib64

Kernel modules, which can be added to the kernel during runtime, are
stored in /lib/modules. All files in these directories
should not be group-writable or world-writable. If any file in these
directories is found to be group-writable or world-writable, correct
its permission with the following command:
$ sudo chmod go-w 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_root\_permissions\_syslibrary\_files
### Title: Verify the system-wide library files in directories
"/lib", "/lib64", "/usr/lib/" and "/usr/lib64" are group-owned by root.
### Description:

```
System-wide library files are stored in the following directories
by default:
/lib
/lib64
/usr/lib
/usr/lib64

All system-wide shared library files should be protected from unauthorised
access. If any of these files is not group-owned by root, correct its group-owner with
the following command:
$ sudo chgrp root 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_autofs\_disabled
### Title: Disable the Automounter
### Description:

```
The autofs daemon mounts and unmounts filesystems, such as user
home directories shared via NFS, on demand. In addition, autofs can be used to handle
removable media, and the default configuration provides the cdrom device as /misc/cd.
However, this method of providing access to removable media is not common, so autofs
can almost always be disabled if NFS is not in use. Even if NFS is required, it may be
possible to configure filesystem mounts statically by editing /etc/fstab
rather than relying on the automounter.


The autofs service can be disabled with the following command:
$ sudo systemctl mask --now autofs.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_cramfs\_disabled
### Title: Disable Mounting of cramfs
### Description:

```
To configure the system to prevent the cramfs
kernel module from being loaded, add the following line to the file /etc/modprobe.d/cramfs.conf:
install cramfs /bin/false

This effectively prevents usage of this uncommon filesystem.

The cramfs filesystem type is a compressed read-only
Linux filesystem embedded in small footprint systems. A
cramfs image can be used without having to first
decompress the image.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_hfs\_disabled
### Title: Disable Mounting of hfs
### Description:

```
To configure the system to prevent the hfs
kernel module from being loaded, add the following line to the file /etc/modprobe.d/hfs.conf:
install hfs /bin/false

This effectively prevents usage of this uncommon filesystem.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_hfsplus\_disabled
### Title: Disable Mounting of hfsplus
### Description:

```
To configure the system to prevent the hfsplus
kernel module from being loaded, add the following line to the file /etc/modprobe.d/hfsplus.conf:
install hfsplus /bin/false

This effectively prevents usage of this uncommon filesystem.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_squashfs\_disabled
### Title: Disable Mounting of squashfs
### Description:

```
To configure the system to prevent the squashfs
kernel module from being loaded, add the following line to the file /etc/modprobe.d/squashfs.conf:
install squashfs /bin/false

This effectively prevents usage of this uncommon filesystem.

The squashfs filesystem type is a compressed read-only Linux
filesystem embedded in small footprint systems (similar to
cramfs). A squashfs image can be used without having
to first decompress the image.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_udf\_disabled
### Title: Disable Mounting of udf
### Description:

```
To configure the system to prevent the udf
kernel module from being loaded, add the following line to the file /etc/modprobe.d/udf.conf:
install udf /bin/false

This effectively prevents usage of this uncommon filesystem.

The udf filesystem type is the universal disk format
used to implement the ISO/IEC 13346 and ECMA-167 specifications.
This is an open vendor filesystem type for data storage on a broad
range of media. This filesystem type is neccessary to support
writing DVDs and newer optical disc formats.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_usb-storage\_disabled
### Title: Disable Modprobe Loading of USB Storage Driver
### Description:

```
To prevent USB storage devices from being used, configure the kernel module loading system
to prevent automatic loading of the USB storage driver.

To configure the system to prevent the usb-storage
kernel module from being loaded, add the following line to the file /etc/modprobe.d/usb-storage.conf:
install usb-storage /bin/false

This will prevent the modprobe program from loading the usb-storage
module, but will not prevent an administrator (or another program) from using the
insmod program to load the module manually.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_dev\_shm\_nodev
### Title: Add nodev Option to /dev/shm
### Description:

```
The nodev mount option can be used to prevent creation of device
files in /dev/shm. Legitimate character and block devices should
not exist within temporary directories like /dev/shm.
Add the nodev option to the fourth column of
/etc/fstab for the line which controls mounting of
/dev/shm.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_dev\_shm\_noexec
### Title: Add noexec Option to /dev/shm
### Description:

```
The noexec mount option can be used to prevent binaries
from being executed out of /dev/shm.
It can be dangerous to allow the execution of binaries
from world-writable temporary storage directories such as /dev/shm.
Add the noexec option to the fourth column of
/etc/fstab for the line which controls mounting of
/dev/shm.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_dev\_shm\_nosuid
### Title: Add nosuid Option to /dev/shm
### Description:

```
The nosuid mount option can be used to prevent execution
of setuid programs in /dev/shm.  The SUID and SGID permissions should not
be required in these world-writable directories.
Add the nosuid option to the fourth column of
/etc/fstab for the line which controls mounting of
/dev/shm.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_home\_nodev
### Title: Add nodev Option to /home
### Description:

```
The nodev mount option can be used to prevent device files from
being created in /home.
Legitimate character and block devices should exist only in
the /dev directory on the root partition or within chroot
jails built for system services.
Add the nodev option to the fourth column of
/etc/fstab for the line which controls mounting of
/home.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_home\_nosuid
### Title: Add nosuid Option to /home
### Description:

```
The nosuid mount option can be used to prevent
execution of setuid programs in /home. The SUID and SGID permissions
should not be required in these user data directories.
Add the nosuid option to the fourth column of
/etc/fstab for the line which controls mounting of
/home.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_tmp\_nodev
### Title: Add nodev Option to /tmp
### Description:

```
The nodev mount option can be used to prevent device files from
being created in /tmp. Legitimate character and block devices
should not exist within temporary directories like /tmp.
Add the nodev option to the fourth column of
/etc/fstab for the line which controls mounting of
/tmp.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_tmp\_noexec
### Title: Add noexec Option to /tmp
### Description:

```
The noexec mount option can be used to prevent binaries
from being executed out of /tmp.
Add the noexec option to the fourth column of
/etc/fstab for the line which controls mounting of
/tmp.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_tmp\_nosuid
### Title: Add nosuid Option to /tmp
### Description:

```
The nosuid mount option can be used to prevent
execution of setuid programs in /tmp. The SUID and SGID permissions
should not be required in these world-writable directories.
Add the nosuid option to the fourth column of
/etc/fstab for the line which controls mounting of
/tmp.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_var\_log\_audit\_nodev
### Title: Add nodev Option to /var/log/audit
### Description:

```
The nodev mount option can be used to prevent device files from
being created in /var/log/audit.
Legitimate character and block devices should exist only in
the /dev directory on the root partition or within chroot
jails built for system services.
Add the nodev option to the fourth column of
/etc/fstab for the line which controls mounting of
/var/log/audit.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_var\_log\_audit\_noexec
### Title: Add noexec Option to /var/log/audit
### Description:

```
The noexec mount option can be used to prevent binaries
from being executed out of /var/log/audit.
Add the noexec option to the fourth column of
/etc/fstab for the line which controls mounting of
/var/log/audit.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_var\_log\_audit\_nosuid
### Title: Add nosuid Option to /var/log/audit
### Description:

```
The nosuid mount option can be used to prevent
execution of setuid programs in /var/log/audit. The SUID and SGID permissions
should not be required in directories containing audit log files.
Add the nosuid option to the fourth column of
/etc/fstab for the line which controls mounting of
/var/log/audit.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_var\_log\_nodev
### Title: Add nodev Option to /var/log
### Description:

```
The nodev mount option can be used to prevent device files from
being created in /var/log.
Legitimate character and block devices should exist only in
the /dev directory on the root partition or within chroot
jails built for system services.
Add the nodev option to the fourth column of
/etc/fstab for the line which controls mounting of
/var/log.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_var\_log\_noexec
### Title: Add noexec Option to /var/log
### Description:

```
The noexec mount option can be used to prevent binaries
from being executed out of /var/log.
Add the noexec option to the fourth column of
/etc/fstab for the line which controls mounting of
/var/log.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_var\_log\_nosuid
### Title: Add nosuid Option to /var/log
### Description:

```
The nosuid mount option can be used to prevent
execution of setuid programs in /var/log. The SUID and SGID permissions
should not be required in directories containing log files.
Add the nosuid option to the fourth column of
/etc/fstab for the line which controls mounting of
/var/log.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_var\_nodev
### Title: Add nodev Option to /var
### Description:

```
The nodev mount option can be used to prevent device files from
being created in /var.
Legitimate character and block devices should exist only in
the /dev directory on the root partition or within chroot
jails built for system services.
Add the nodev option to the fourth column of
/etc/fstab for the line which controls mounting of
/var.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_var\_nosuid
### Title: Add nosuid Option to /var
### Description:

```
The nosuid mount option can be used to prevent
execution of setuid programs in /var. The SUID and SGID permissions
should not be required for this directory.
Add the nosuid option to the fourth column of
/etc/fstab for the line which controls mounting of
/var.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_var\_tmp\_nodev
### Title: Add nodev Option to /var/tmp
### Description:

```
The nodev mount option can be used to prevent device files from
being created in /var/tmp. Legitimate character and block devices
should not exist within temporary directories like /var/tmp.
Add the nodev option to the fourth column of
/etc/fstab for the line which controls mounting of
/var/tmp.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_var\_tmp\_noexec
### Title: Add noexec Option to /var/tmp
### Description:

```
The noexec mount option can be used to prevent binaries
from being executed out of /var/tmp.
Add the noexec option to the fourth column of
/etc/fstab for the line which controls mounting of
/var/tmp.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_mount\_option\_var\_tmp\_nosuid
### Title: Add nosuid Option to /var/tmp
### Description:

```
The nosuid mount option can be used to prevent
execution of setuid programs in /var/tmp. The SUID and SGID permissions
should not be required in these world-writable directories.
Add the nosuid option to the fourth column of
/etc/fstab for the line which controls mounting of
/var/tmp.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_uvcvideo\_disabled
### Title: Disable the uvcvideo module
### Description:

```
If the device contains a camera it should be covered or disabled when not in use.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_kernel\_dmesg\_restrict
### Title: Restrict Access to Kernel Message Buffer
### Description:

```
To set the runtime status of the kernel.dmesg_restrict kernel parameter, run the following command: $ sudo sysctl -w kernel.dmesg_restrict=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: kernel.dmesg_restrict = 1
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_kernel\_panic\_on\_oops
### Title: Kernel panic on oops
### Description:

```
To set the runtime status of the kernel.panic_on_oops kernel parameter, run the following command: $ sudo sysctl -w kernel.panic_on_oops=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: kernel.panic_on_oops = 1
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_coredump\_disable\_backtraces
### Title: Disable core dump backtraces
### Description:

```
The ProcessSizeMax option in [Coredump] section
of /etc/systemd/coredump.conf
specifies the maximum size in bytes of a core which will be processed.
Core dumps exceeding this size may be stored, but the backtrace will not
be generated.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_coredump\_disable\_storage
### Title: Disable storing core dump
### Description:

```
The Storage option in [Coredump] section
of /etc/systemd/coredump.conf
can be set to none to disable storing core dumps permanently.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_disable\_users\_coredumps
### Title: Disable Core Dumps for All Users
### Description:

```
To disable core dumps for all users, add the following line to
/etc/security/limits.conf, or to a file within the
/etc/security/limits.d/ directory:
*     hard   core    0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_fs\_suid\_dumpable
### Title: Disable Core Dumps for SUID programs
### Description:

```
To set the runtime status of the fs.suid_dumpable kernel parameter, run the following command: $ sudo sysctl -w fs.suid_dumpable=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: fs.suid_dumpable = 0
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_kernel\_kptr\_restrict
### Title: Restrict Exposed Kernel Pointer Addresses Access
### Description:

```
To set the runtime status of the kernel.kptr_restrict kernel parameter, run the following command: $ sudo sysctl -w kernel.kptr_restrict=
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: kernel.kptr_restrict = 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_kernel\_randomize\_va\_space
### Title: Enable Randomized Layout of Virtual Address Space
### Description:

```
To set the runtime status of the kernel.randomize_va_space kernel parameter, run the following command: $ sudo sysctl -w kernel.randomize_va_space=2
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: kernel.randomize_va_space = 2
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_bios\_enable\_execution\_restrictions
### Title: Enable NX or XD Support in the BIOS
### Description:

```
Reboot the system and enter the BIOS or Setup configuration menu.
Navigate the BIOS configuration menu and make sure that the option is enabled. The setting may be located
under a Security section. Look for Execute Disable (XD) on Intel-based systems and No Execute (NX)
on AMD-based systems.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_selinux\_state
### Title: Ensure SELinux State is Enforcing
### Description:

```
The SELinux state should be set to  at
system boot time.  In the file /etc/selinux/config, add or correct the
following line to configure the system to boot into enforcing mode:
SELINUX=
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_apport\_disabled
### Title: Disable Apport Service
### Description:

```
The Apport modifies certain kernel configuration values at
runtime which may decrease the overall security of the system and expose sensitive data.

The apport service can be disabled with the following command:
$ sudo systemctl mask --now apport.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_apt\_conf\_disallow\_unauthenticated
### Title: Disable unauthenticated repositories in APT configuration
### Description:

```
Unauthenticated repositories should not be used for updates.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_avahi\_disable\_publishing
### Title: Disable Avahi Publishing
### Description:

```
To prevent Avahi from publishing its records, edit /etc/avahi/avahi-daemon.conf
and ensure the following line appears in the [publish] section:
disable-publishing=yes
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_avahi\_removed
### Title: Uninstall avahi Server Package
### Description:

```
If the system does not need to have an Avahi server which implements
the DNS Service Discovery and Multicast DNS protocols,
the avahi-autoipd and avahi packages can be uninstalled.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_avahi-daemon\_disabled
### Title: Disable Avahi Server Software
### Description:

```
The avahi-daemon service can be disabled with the following command:
$ sudo systemctl mask --now avahi-daemon.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_kdump\_disabled
### Title: Disable KDump Kernel Crash Analyzer (kdump)
### Description:

```
The kdump-tools service provides a kernel crash dump analyzer. It uses the kexec
system call to boot a secondary kernel ("capture" kernel) following a system
crash, which can load information from the crashed kernel for analysis.

The kdump-tools service can be disabled with the following command:
$ sudo systemctl mask --now kdump-tools.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_cron\_installed
### Title: Install the cron service
### Description:

```
The Cron service should be installed.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_cron\_enabled
### Title: Enable cron Service
### Description:

```
The crond service is used to execute commands at
preconfigured times. It is required by almost all systems to perform necessary
maintenance tasks, such as notifying root of system activity.

The cron service can be enabled with the following command:
$ sudo systemctl enable cron.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_cron\_d
### Title: Verify Group Who Owns cron.d
### Description:

```
To properly set the group owner of /etc/cron.d, run the command:
$ sudo chgrp root /etc/cron.d
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_cron\_daily
### Title: Verify Group Who Owns cron.daily
### Description:

```
To properly set the group owner of /etc/cron.daily, run the command:
$ sudo chgrp root /etc/cron.daily
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_cron\_hourly
### Title: Verify Group Who Owns cron.hourly
### Description:

```
To properly set the group owner of /etc/cron.hourly, run the command:
$ sudo chgrp root /etc/cron.hourly
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_cron\_monthly
### Title: Verify Group Who Owns cron.monthly
### Description:

```
To properly set the group owner of /etc/cron.monthly, run the command:
$ sudo chgrp root /etc/cron.monthly
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_cron\_weekly
### Title: Verify Group Who Owns cron.weekly
### Description:

```
To properly set the group owner of /etc/cron.weekly, run the command:
$ sudo chgrp root /etc/cron.weekly
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_crontab
### Title: Verify Group Who Owns Crontab
### Description:

```
To properly set the group owner of /etc/crontab, run the command:
$ sudo chgrp root /etc/crontab
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_cron\_d
### Title: Verify Owner on cron.d
### Description:

```
To properly set the owner of /etc/cron.d, run the command:
$ sudo chown root /etc/cron.d 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_cron\_daily
### Title: Verify Owner on cron.daily
### Description:

```
To properly set the owner of /etc/cron.daily, run the command:
$ sudo chown root /etc/cron.daily 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_cron\_hourly
### Title: Verify Owner on cron.hourly
### Description:

```
To properly set the owner of /etc/cron.hourly, run the command:
$ sudo chown root /etc/cron.hourly 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_cron\_monthly
### Title: Verify Owner on cron.monthly
### Description:

```
To properly set the owner of /etc/cron.monthly, run the command:
$ sudo chown root /etc/cron.monthly 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_cron\_weekly
### Title: Verify Owner on cron.weekly
### Description:

```
To properly set the owner of /etc/cron.weekly, run the command:
$ sudo chown root /etc/cron.weekly 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_crontab
### Title: Verify Owner on crontab
### Description:

```
To properly set the owner of /etc/crontab, run the command:
$ sudo chown root /etc/crontab 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_cron\_d
### Title: Verify Permissions on cron.d
### Description:

```
To properly set the permissions of /etc/cron.d, run the command:
$ sudo chmod 0700 /etc/cron.d
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_cron\_daily
### Title: Verify Permissions on cron.daily
### Description:

```
To properly set the permissions of /etc/cron.daily, run the command:
$ sudo chmod 0700 /etc/cron.daily
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_cron\_hourly
### Title: Verify Permissions on cron.hourly
### Description:

```
To properly set the permissions of /etc/cron.hourly, run the command:
$ sudo chmod 0700 /etc/cron.hourly
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_cron\_monthly
### Title: Verify Permissions on cron.monthly
### Description:

```
To properly set the permissions of /etc/cron.monthly, run the command:
$ sudo chmod 0700 /etc/cron.monthly
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_cron\_weekly
### Title: Verify Permissions on cron.weekly
### Description:

```
To properly set the permissions of /etc/cron.weekly, run the command:
$ sudo chmod 0700 /etc/cron.weekly
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_crontab
### Title: Verify Permissions on crontab
### Description:

```
To properly set the permissions of /etc/crontab, run the command:
$ sudo chmod 0600 /etc/crontab
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_at\_deny\_not\_exist
### Title: Ensure that /etc/at.deny does not exist
### Description:

```
The file /etc/at.deny should not exist.
Use /etc/at.allow instead.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_cron\_deny\_not\_exist
### Title: Ensure that /etc/cron.deny does not exist
### Description:

```
The file /etc/cron.deny should not exist.
Use /etc/cron.allow instead.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_at\_allow
### Title: Verify Group Who Owns /etc/at.allow file
### Description:

```
If /etc/at.allow exists, it must be group-owned by root.

To properly set the group owner of /etc/at.allow, run the command:
$ sudo chgrp root /etc/at.allow
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_cron\_allow
### Title: Verify Group Who Owns /etc/cron.allow file
### Description:

```
If /etc/cron.allow exists, it must be group-owned by crontab.

To properly set the group owner of /etc/cron.allow, run the command:
$ sudo chgrp crontab /etc/cron.allow
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_at\_allow
### Title: Verify User Who Owns /etc/at.allow file
### Description:

```
If /etc/at.allow exists, it must be owned by root.

To properly set the owner of /etc/at.allow, run the command:
$ sudo chown root /etc/at.allow 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_cron\_allow
### Title: Verify User Who Owns /etc/cron.allow file
### Description:

```
If /etc/cron.allow exists, it must be owned by root.

To properly set the owner of /etc/cron.allow, run the command:
$ sudo chown root /etc/cron.allow 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_at\_allow
### Title: Verify Permissions on /etc/at.allow file
### Description:

```
If /etc/at.allow exists, it must have permissions 0640
or more restrictive.


To properly set the permissions of /etc/at.allow, run the command:
$ sudo chmod 0640 /etc/at.allow
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_cron\_allow
### Title: Verify Permissions on /etc/cron.allow file
### Description:

```
If /etc/cron.allow exists, it must have permissions 0640
or more restrictive.


To properly set the permissions of /etc/cron.allow, run the command:
$ sudo chmod 0640 /etc/cron.allow
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_inetutils-telnetd\_removed
### Title: Uninstall the inet-based telnet server
### Description:

```
The inet-based telnet daemon should be uninstalled.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_nis\_removed
### Title: Uninstall the nis package
### Description:

```
The support for Yellowpages should not be installed unless it is required.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_ntpdate\_removed
### Title: Uninstall the ntpdate package
### Description:

```
ntpdate is a historical ntp synchronization client for unixes. It sould be uninstalled.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_telnetd-ssl\_removed
### Title: Uninstall the ssl compliant telnet server
### Description:

```
The telnet daemon, even with ssl support, should be uninstalled.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_telnetd\_removed
### Title: Uninstall the telnet server
### Description:

```
The telnet daemon should be uninstalled.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dhcp\_client\_restrict\_options
### Title: Minimize the DHCP-Configured Options
### Description:

```
Create the file /etc/dhcp/dhclient.conf, and add an
appropriate setting for each of the ten configuration settings which can be
obtained via DHCP. For each setting, do one of the following:

If the setting should not be configured remotely by the DHCP server,
select an appropriate static value, and add the line:
supersede 
If the setting should be configured remotely by the DHCP server, add the lines:
request 
For example, suppose the DHCP server should provide only the IP address itself
and the subnet mask. Then the entire file should look like:
supersede domain-name "example.com";
supersede domain-name-servers 192.168.1.2;
supersede nis-domain "";
supersede nis-servers "";
supersede ntp-servers "ntp.example.com ";
supersede routers 192.168.1.1;
supersede time-offset -18000;
request subnet-mask;
require subnet-mask;
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_dhcp\_server\_minimize\_served\_info
### Title: Minimize Served Information
### Description:

```
Edit /etc/dhcp/dhcpd.conf. Examine each address range section within
the file, and ensure that the following options are not defined unless there is
an operational need to provide this information via DHCP:
option domain-name
option domain-name-servers
option nis-domain
option nis-servers
option ntp-servers
option routers
option time-offset
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_dhcp\_removed
### Title: Uninstall DHCP Server Package
### Description:

```
If the system does not need to act as a DHCP server,
the dhcp package can be uninstalled.

The isc-dhcp-server package can be removed with the following command:

$ apt-get remove isc-dhcp-server
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_bind\_removed
### Title: Uninstall bind Package
### Description:

```
The named service is provided by the bind package.
The bind package can be removed with the following command:

$ apt-get remove bind
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_fapolicyd\_prevent\_home\_folder\_access
### Title: fapolicyd Must be Configured to Limit Access to Users Home Folders
### Description:

```
fapolicyd needs be configured so that users cannot give access to their home folders to other users.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_vsftpd\_removed
### Title: Uninstall vsftpd Package
### Description:

```
The vsftpd package can be removed with the following command:  $ apt-get remove vsftpd
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ftp\_configure\_firewall
### Title: Configure Firewalls to Protect the FTP Server
### Description:

```
By default, iptables
blocks access to the ports used by the web server.

To configure iptables to allow port 21 traffic, one must edit
/etc/sysconfig/iptables and
/etc/sysconfig/ip6tables (if IPv6 is in use).
Add the following line, ensuring that it appears before the final LOG and DROP lines for the INPUT chain:
-A INPUT -m state --state NEW -p tcp --dport 21 -j ACCEPT
Edit the file /etc/sysconfig/iptables-config. Ensure that the space-separated list of modules contains
the FTP connection tracking module:
IPTABLES_MODULES="ip_conntrack_ftp"
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ftp\_limit\_users
### Title: Limit Users Allowed FTP Access if Necessary
### Description:

```
If there is a mission-critical reason for users to access their accounts via the insecure FTP protocol, limit the set of users who are allowed this access. Edit the vsftpd configuration file. Add or correct the following configuration options:
userlist_enable=YES
userlist_file=/etc/vsftp.ftpusers
userlist_deny=NO
Edit the file /etc/vsftp.ftpusers. For each user USERNAME who should be allowed to access the system via FTP, add a line containing that user's name:
USERNAME
If anonymous access is also required, add the anonymous usernames to /etc/vsftp.ftpusers as well.
anonymous
ftp
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_httpd\_removed
### Title: Uninstall httpd Package
### Description:

```
The apache2 package can be removed with the following command:

$ apt-get remove apache2
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_nginx\_removed
### Title: Uninstall nginx Package
### Description:

```
The nginx package can be removed with the following command:

$ apt-get remove nginx
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_cyrus-imapd\_removed
### Title: Uninstall cyrus-imapd Package
### Description:

```
The cyrus-imapd package can be removed with the following command:

$ apt-get remove cyrus-imapd
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_dovecot\_removed
### Title: Uninstall dovecot Package
### Description:

```
The dovecot-core package can be removed with the following command:

$ apt-get remove dovecot-core
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_openldap-clients\_removed
### Title: Ensure LDAP client is not installed
### Description:

```
The Lightweight Directory Access Protocol (LDAP) is a service that provides
a method for looking up information from a central database.
The lapd-utils package can be removed with the following command:

$ apt-get remove lapd-utils
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_openldap-servers\_removed
### Title: Uninstall openldap-servers Package
### Description:

```
The slapd package is not installed by default on a Ubuntu 22.04
system. It is needed only by the OpenLDAP server, not by the
clients which use LDAP for authentication. If the system is not
intended for use as an LDAP Server it should be removed.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_postfix\_installed
### Title: The Postfix package is installed
### Description:

```
A mail server is required for sending emails.
The postfix package can be installed with the following command:

$ apt-get install postfix
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_postfix\_enabled
### Title: Enable Postfix Service
### Description:

```
The Postfix mail transfer agent is used for local mail delivery
within the system. The default configuration only listens for connections to
the default SMTP port (port 25) on the loopback interface (127.0.0.1).  It is
recommended to leave this service enabled for local mail delivery.

The postfix service can be enabled with the following command:
$ sudo systemctl enable postfix.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_has\_nonlocal\_mta
### Title: Ensure Mail Transfer Agent is not Listening on any non-loopback Address
### Description:

```
Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to
listen for incoming mail and transfer the messages to the appropriate
user or mail server. If the system is not intended to be a mail server,
it is recommended that the MTA be configured to only process local mail.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_postfix\_client\_configure\_mail\_alias
### Title: Configure System to Forward All Mail For The Root Account
### Description:

```
Make sure that mails delivered to root user are forwarded to a monitored
email address. Make sure that the address
 is a valid email address
reachable from the system in question. Use the following command to
configure the alias:
$ sudo echo "root: 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_postfix\_client\_configure\_mail\_alias\_postmaster
### Title: Configure System to Forward All Mail From Postmaster to The Root Account
### Description:

```
Verify the administrators are notified in the event of an audit processing failure.
Check that the "/etc/aliases" file has a defined value for "root".
$ sudo grep "postmaster:\s*root$" /etc/aliases

postmaster: root
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_postfix\_client\_configure\_relayhost
### Title: Configure System to Forward All Mail through a specific host
### Description:

```
Set up a relay host that will act as a gateway for all outbound email.
Edit the file /etc/postfix/main.cf to ensure that only the following
relayhost line appears:
relayhost = 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_postfix\_network\_listening\_disabled
### Title: Disable Postfix Network Listening
### Description:

```
Edit the file /etc/postfix/main.cf to ensure that only the following
inet_interfaces line appears:
inet_interfaces = 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_nfs-kernel-server\_removed
### Title: Uninstall nfs-kernel-server Package
### Description:

```
The nfs-kernel-server package can be removed with the following command:

$ apt-get remove nfs-kernel-server
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_netfs\_disabled
### Title: Disable Network File Systems (netfs)
### Description:

```
The netfs script manages the boot-time mounting of several types
of networked filesystems, of which NFS and Samba are the most common. If these
filesystem types are not in use, the script can be disabled, protecting the
system somewhat against accidental or malicious changes to /etc/fstab
and against flaws in the netfs script itself.

The netfs service can be disabled with the following command:
$ sudo systemctl mask --now netfs.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_rpcbind\_removed
### Title: Uninstall rpcbind Package
### Description:

```
The rpcbind utility maps RPC services to the ports on which they listen.
RPC processes notify rpcbind when they start, registering the ports they
are listening on and the RPC program numbers they expect to serve. The
rpcbind service redirects the client to the proper port number so it can
communicate with the requested service. If the system does not require RPC
(such as for NFS servers) then this service should be disabled.
The rpcbind package can be removed with the following command:

$ apt-get remove rpcbind
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_all\_squash\_exports
### Title: Ensure All-Squashing Disabled On All Exports
### Description:

```
The all_squash maps all uids and gids to an anonymous user.
This should be disabled by removing any instances of the
all_squash option from the file /etc/exports.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_chrony\_installed
### Title: The Chrony package is installed
### Description:

```
System time should be synchronized between all systems in an environment. This is
typically done by establishing an authoritative time server or set of servers and having all
systems synchronize their clocks to them.
The chrony package can be installed with the following command:

$ apt-get install chrony
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_ntp\_installed
### Title: Install the ntp service
### Description:

```
The ntpd service should be installed.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_timesyncd\_installed
### Title: Install the systemd\_timesyncd Service
### Description:

```
The systemd_timesyncd service should be installed.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_ntp\_removed
### Title: Remove the ntp service
### Description:

```
The ntpd service should not be installed.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_timesyncd\_removed
### Title: Remove the systemd\_timesyncd Service
### Description:

```
The systemd_timesyncd service should not be installed.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_chronyd\_enabled
### Title: The Chronyd service is enabled
### Description:

```
chrony is a daemon which implements the Network Time Protocol (NTP) is designed to
synchronize system clocks across a variety of systems and use a source that is highly
accurate. More information on chrony can be found at

    http://chrony.tuxfamily.org/.
Chrony can be configured to be a client and/or a server.
To enable Chronyd service, you can run:
# systemctl enable chronyd.service
This recommendation only applies if chrony is in use on the system.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_ntp\_enabled
### Title: Enable the NTP Daemon
### Description:

```
The ntp service can be enabled with the following command:
$ sudo systemctl enable ntp.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_ntpd\_enabled
### Title: Enable the NTP Daemon
### Description:

```
The ntpd service can be enabled with the following command:
$ sudo systemctl enable ntpd.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_timesyncd\_enabled
### Title: Enable systemd\_timesyncd Service
### Description:

```
The systemd_timesyncd service can be enabled with the following command:
$ sudo systemctl enable systemd_timesyncd.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_chronyd\_or\_ntpd\_set\_maxpoll
### Title: Configure Time Service Maxpoll Interval
### Description:

```
The maxpoll should be configured to
 in /etc/ntp.conf or
/etc/chrony/chrony.conf (or /etc/chrony/conf.d/) to continuously poll time servers. To configure
maxpoll in /etc/ntp.conf or /etc/chrony/chrony.conf (or /etc/chrony/conf.d/)
add the following after each server, pool or peer entry:
maxpoll 
to server directives. If using chrony, any pool directives
should be configured too.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_chronyd\_run\_as\_chrony\_user
### Title: Ensure that chronyd is running under chrony user account
### Description:

```
chrony is a daemon which implements the Network Time Protocol (NTP). It is designed to
synchronize system clocks across a variety of systems and use a source that is highly
accurate. More information on chrony can be found at

    http://chrony.tuxfamily.org/.
Chrony can be configured to be a client and/or a server.
To ensure that chronyd is running under chrony user account,

user variable in /etc/chrony/chrony.conf is set to _chrony or is
absent:
user _chrony

This recommendation only applies if chrony is in use on the system.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_chronyd\_server\_directive
### Title: Ensure Chrony is only configured with the server directive
### Description:

```
Check that Chrony only has time sources configured with the server directive.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_chronyd\_specify\_remote\_server
### Title: A remote time server for Chrony is configured
### Description:

```
Chrony is a daemon which implements the Network Time Protocol (NTP). It is designed to
synchronize system clocks across a variety of systems and use a source that is highly
accurate. More information on chrony can be found at

    http://chrony.tuxfamily.org/.
Chrony can be configured to be a client and/or a server.
Add or edit server or pool lines to /etc/chrony/chrony.conf as appropriate:
server <remote-server>
Multiple servers may be configured.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_chronyd\_sync\_clock
### Title: Synchronize internal information system clocks
### Description:

```
Synchronizing internal information system clocks provides uniformity
of time stamps for information systems with multiple system clocks and
systems connected over a network.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ntpd\_configure\_restrictions
### Title: Configure server restrictions for ntpd
### Description:

```
ntpd is a daemon which implements the Network Time Protocol (NTP). It is designed to
synchronize system clocks across a variety of systems and use a source that is highly
accurate. More information on NTP can be found at

    http://www.ntp.org.
ntp can be configured to be a client and/or a server.
To ensure that ntpd implements correct server restrictions, make sure that the following lines exist in the file /etc/ntpd.conf:
restrict -4 default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery
This recommendation only applies if ntp is in use on the system.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ntpd\_run\_as\_ntp\_user
### Title: Configure ntpd To Run As ntp User
### Description:

```
ntp is a daemon which implements the Network Time Protocol (NTP). It is designed to
synchronize system clocks across a variety of systems and use a source that is highly
accurate. More information on NTP can be found at

    http://www.ntp.org.
ntp can be configured to be a client and/or a server.
To ensure that ntpd is running as ntp user, Add or edit the
OPTIONS variable in /etc/sysconfig/ntpd to include ' -u ntp:ntp ':
OPTIONS="-u ntp:ntp"
This recommendation only applies if ntp is in use on the system.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ntpd\_specify\_multiple\_servers
### Title: Specify Additional Remote NTP Servers
### Description:

```
Additional NTP servers can be specified for time synchronization
in the file /etc/ntp.conf.  To do so, add additional lines of the
following form, substituting the IP address or hostname of a remote NTP server for
ntpserver:
server 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ntpd\_specify\_remote\_server
### Title: Specify a Remote NTP Server
### Description:

```
To specify a remote NTP server for time synchronization, edit
the file /etc/ntp.conf. Add or correct the following lines,
substituting the IP or hostname of a remote NTP server for ntpserver:
server 
This instructs the NTP software to contact that remote server to obtain time
data.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_rsync\_removed
### Title: Uninstall rsync Package
### Description:

```
The rsyncd service can be used to synchronize files between systems over network links.
The rsync package can be removed with the following command:

$ apt-get remove rsync
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_xinetd\_removed
### Title: Uninstall xinetd Package
### Description:

```
The xinetd package can be removed with the following command:

$ apt-get remove xinetd
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_rsh-server\_removed
### Title: Uninstall rsh-server Package
### Description:

```
The rsh-server package can be removed with the following command:

$ apt-get remove rsh-server
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_rsh\_removed
### Title: Uninstall rsh Package
### Description:

```
The rsh-client package contains the client commands

for the rsh services
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_rsh\_trust\_files
### Title: Remove Rsh Trust Files
### Description:

```
The files /etc/hosts.equiv and ~/.rhosts (in
each user's home directory) list remote hosts and users that are trusted by the
local system when using the rshd daemon.
To remove these files, run the following command to delete them from any
location:
$ sudo rm /etc/hosts.equiv
$ rm ~/.rhosts
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_talk\_removed
### Title: Uninstall talk Package
### Description:

```
The talk package contains the client program for the
Internet talk protocol, which allows the user to chat with other users on
different systems. Talk is a communication program which copies lines from one
terminal to the terminal of another user.
The talk package can be removed with the following command:

$ apt-get remove talk
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_telnet\_removed
### Title: Remove telnet Clients
### Description:

```
The telnet client allows users to start connections to other systems via
the telnet protocol.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_cups\_removed
### Title: Uninstall CUPS Package
### Description:

```
The cups package can be removed with the following command:

$ apt-get remove cups
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_cups\_disabled
### Title: Disable the CUPS Service
### Description:

```
The cups service can be disabled with the following command:
$ sudo systemctl mask --now cups.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_squid\_removed
### Title: Uninstall squid Package
### Description:

```
The squid package can be removed with the following command:  $ apt-get remove squid
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_samba\_removed
### Title: Uninstall Samba Package
### Description:

```
The samba package can be removed with the following command:  $ apt-get remove samba
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_net-snmp\_removed
### Title: Uninstall net-snmp Package
### Description:

```
The snmp package provides the snmpd service.
The snmp package can be removed with the following command:

$ apt-get remove snmp
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_openssh-server\_installed
### Title: Install the OpenSSH Server Package
### Description:

```
The openssh-server package should be installed.
The openssh-server package can be installed with the following command:

$ apt-get install openssh-server
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_openssh-server\_removed
### Title: Remove the OpenSSH Server Package
### Description:

```
The openssh-server package should be removed.
The openssh-server package can be removed with the following command:

$ apt-get remove openssh-server
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_sshd\_enabled
### Title: Enable the OpenSSH Service
### Description:

```
The SSH server service, sshd, is commonly needed.

The sshd service can be enabled with the following command:
$ sudo systemctl enable sshd.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_sshd\_disabled
### Title: Disable SSH Server If Possible (Unusual)
### Description:

```
The SSH server service, sshd, is commonly needed.
However, if it can be disabled, do so.


The sshd service can be disabled with the following command:
$ sudo systemctl mask --now sshd.service

This is unusual, as SSH is a common method for encrypted and authenticated
remote access.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_sshd\_config
### Title: Verify Group Who Owns SSH Server config file
### Description:

```
To properly set the group owner of /etc/ssh/sshd_config, run the command:
$ sudo chgrp root /etc/ssh/sshd_config
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownership\_sshd\_private\_key
### Title: Verify Group Ownership on SSH Server Private \*\_key Key Files
### Description:

```
SSH server private keys, files that match the /etc/ssh/*_key glob, must be
group-owned by root group.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownership\_sshd\_pub\_key
### Title: Verify Group Ownership on SSH Server Public \*.pub Key Files
### Description:

```
SSH server public keys, files that match the /etc/ssh/*.pub glob, must be
group-owned by root group.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_sshd\_config
### Title: Verify Owner on SSH Server config file
### Description:

```
To properly set the owner of /etc/ssh/sshd_config, run the command:
$ sudo chown root /etc/ssh/sshd_config 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_sshd\_config
### Title: Verify Permissions on SSH Server config file
### Description:

```
To properly set the permissions of /etc/ssh/sshd_config, run the command:
$ sudo chmod 0600 /etc/ssh/sshd_config
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_sshd\_private\_key
### Title: Verify Permissions on SSH Server Private \*\_key Key Files
### Description:

```
SSH server private keys - files that match the /etc/ssh/*_key glob, have to have restricted permissions.
If those files are owned by the root user and the root group, they have to have the 0600 permission or stricter.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_sshd\_pub\_key
### Title: Verify Permissions on SSH Server Public \*.pub Key Files
### Description:

```
 To properly set the permissions of /etc/ssh/*.pub, run the command: $ sudo chmod 0644 /etc/ssh/*.pub
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_iptables\_sshd\_disabled
### Title: Remove SSH Server iptables Firewall exception (Unusual)
### Description:

```
By default, inbound connections to SSH's port are allowed. If the SSH
server is not being used, this exception should be removed from the
firewall configuration.

Edit the files /etc/sysconfig/iptables and
/etc/sysconfig/ip6tables (if IPv6 is in use). In each file, locate
and delete the line:
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
This is unusual, as SSH is a common method for encrypted and authenticated
remote access.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_set\_keepalive\_0
### Title: Set SSH Client Alive Count Max to zero
### Description:

```
The SSH server sends at most ClientAliveCountMax messages
during a SSH session and waits for a response from the SSH client.
The option ClientAliveInterval configures timeout after
each ClientAliveCountMax message. If the SSH server does not
receive a response from the client, then the connection is considered unresponsive
and terminated.

To ensure the SSH timeout occurs precisely when the
ClientAliveInterval is set, set the ClientAliveCountMax to
value of 0 in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_set\_keepalive
### Title: Set SSH Client Alive Count Max
### Description:

```
The SSH server sends at most ClientAliveCountMax messages
during a SSH session and waits for a response from the SSH client.
The option ClientAliveInterval configures timeout after
each ClientAliveCountMax message. If the SSH server does not
receive a response from the client, then the connection is considered unresponsive
and terminated.
For SSH earlier than v8.2, a ClientAliveCountMax value of 0
causes a timeout precisely when the ClientAliveInterval is set.
Starting with v8.2, a value of 0 disables the timeout functionality
completely. If the option is set to a number greater than 0, then
the session will be disconnected after
ClientAliveInterval * ClientAliveCountMax seconds without receiving
a keep alive message.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_set\_idle\_timeout
### Title: Set SSH Client Alive Interval
### Description:

```
SSH allows administrators to set a network responsiveness timeout interval.
After this interval has passed, the unresponsive client will be automatically logged out.

To set this timeout interval, edit the following line in /etc/ssh/sshd_config as
follows:
ClientAliveInterval 

The timeout interval is given in seconds. For example, have a timeout
of 10 minutes, set interval to 600.

If a shorter timeout has already been set for the login shell, that value will
preempt any SSH setting made in /etc/ssh/sshd_config. Keep in mind that
some processes may stop SSH from correctly detecting that the user is idle.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_disable\_host\_auth
### Title: Disable Host-Based Authentication
### Description:

```
SSH's cryptographic host-based authentication is
more secure than .rhosts authentication. However, it is
not recommended that hosts unilaterally trust one another, even
within an organization.

The default SSH configuration disables host-based authentication. The appropriate
configuration is used if no value is set for HostbasedAuthentication.

To explicitly disable host-based authentication, add or correct the
following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

HostbasedAuthentication no
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_allow\_only\_protocol2
### Title: Allow Only SSH Protocol 2
### Description:

```
Only SSH protocol version 2 connections should be
permitted. The default setting in
/etc/ssh/sshd_config is correct, and can be
verified by ensuring that the following
line appears:
Protocol 2
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_compression
### Title: Disable Compression Or Set Compression to delayed
### Description:

```
Compression is useful for slow network connections over long
distances but can cause performance issues on local LANs. If use of compression
is required, it should be enabled only after a user has authenticated; otherwise,
it should be disabled. To disable compression or delay compression until after
a user has successfully authenticated, add or correct the following line in the
/etc/ssh/sshd_config file:
Compression 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_empty\_passwords
### Title: Disable SSH Access via Empty Passwords
### Description:

```
Disallow SSH login with empty passwords.
The default SSH configuration disables logins with empty passwords. The appropriate
configuration is used if no value is set for PermitEmptyPasswords.

To explicitly disallow SSH login from accounts with empty passwords,
add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:


PermitEmptyPasswords no
Any accounts with empty passwords should be disabled immediately, and PAM configuration
should prevent users from being able to assign themselves empty passwords.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_gssapi\_auth
### Title: Disable GSSAPI Authentication
### Description:

```
Unless needed, SSH should not permit extraneous or unnecessary
authentication mechanisms like GSSAPI.

The default SSH configuration disallows authentications based on GSSAPI. The appropriate
configuration is used if no value is set for GSSAPIAuthentication.

To explicitly disable GSSAPI authentication, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

GSSAPIAuthentication no
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_kerb\_auth
### Title: Disable Kerberos Authentication
### Description:

```
Unless needed, SSH should not permit extraneous or unnecessary
authentication mechanisms like Kerberos.

The default SSH configuration disallows authentication validation through Kerberos.
The appropriate configuration is used if no value is set for KerberosAuthentication.

To explicitly disable Kerberos authentication, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

KerberosAuthentication no
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_pubkey\_auth
### Title: Disable PubkeyAuthentication Authentication
### Description:

```
Unless needed, SSH should not permit extraneous or unnecessary
authentication mechanisms. To disable PubkeyAuthentication authentication, add or
correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

PubkeyAuthentication no
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_rhosts
### Title: Disable SSH Support for .rhosts Files
### Description:

```
SSH can emulate the behavior of the obsolete rsh
command in allowing users to enable insecure access to their
accounts via .rhosts files.

The default SSH configuration disables support for .rhosts. The appropriate
configuration is used if no value is set for IgnoreRhosts.

To explicitly disable support for .rhosts files, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

IgnoreRhosts yes
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_rhosts\_rsa
### Title: Disable SSH Support for Rhosts RSA Authentication
### Description:

```
SSH can allow authentication through the obsolete rsh
command through the use of the authenticating user's SSH keys. This should be disabled.

To ensure this behavior is disabled, add or correct the
following line in /etc/ssh/sshd_config:
RhostsRSAAuthentication no
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_root\_login
### Title: Disable SSH Root Login
### Description:

```
The root user should never be allowed to login to a
system directly over a network.
To disable root login via SSH, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

PermitRootLogin no
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_root\_password\_login
### Title: Disable SSH root Login with a Password (Insecure)
### Description:

```
To disable password-based root logins over SSH, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

PermitRootLogin prohibit-password
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_tcp\_forwarding
### Title: Disable SSH TCP Forwarding
### Description:

```
The AllowTcpForwarding parameter specifies whether TCP forwarding is permitted.
To disable TCP forwarding, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

AllowTcpForwarding no
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_user\_known\_hosts
### Title: Disable SSH Support for User Known Hosts
### Description:

```
SSH can allow system users to connect to systems if a cache of the remote
systems public keys is available.  This should be disabled.

To ensure this behavior is disabled, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

IgnoreUserKnownHosts yes
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_x11\_forwarding
### Title: Disable X11 Forwarding
### Description:

```
The X11Forwarding parameter provides the ability to tunnel X11 traffic
through the connection to enable remote graphic connections.
SSH has the capability to encrypt remote X11 connections when SSH's
X11Forwarding option is enabled.

The default SSH configuration disables X11Forwarding. The appropriate
configuration is used if no value is set for X11Forwarding.

To explicitly disable X11 Forwarding, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

X11Forwarding no
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_do\_not\_permit\_user\_env
### Title: Do Not Allow SSH Environment Options
### Description:

```
Ensure that users are not able to override environment variables of the SSH daemon.

The default SSH configuration disables environment processing. The appropriate
configuration is used if no value is set for PermitUserEnvironment.

To explicitly disable Environment options, add or correct the following


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

PermitUserEnvironment no
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_enable\_gssapi\_auth
### Title: Enable GSSAPI Authentication
### Description:

```
Sites setup to use Kerberos or other GSSAPI Authenticaion require setting
sshd to accept this authentication.
To enable GSSAPI authentication, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

GSSAPIAuthentication yes
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_enable\_pam
### Title: Enable PAM
### Description:

```
UsePAM Enables the Pluggable Authentication Module interface. If set to “yes” this will
enable PAM authentication using ChallengeResponseAuthentication and
PasswordAuthentication in addition to PAM account and session module processing for all
authentication types.

To enable PAM authentication, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

UsePAM yes
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_enable\_pubkey\_auth
### Title: Enable Public Key Authentication
### Description:

```
Enable SSH login with public keys.

The default SSH configuration enables authentication based on public keys. The appropriate
configuration is used if no value is set for PubkeyAuthentication.

To explicitly enable Public Key Authentication, add or correct the following


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

PubkeyAuthentication yes
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_enable\_strictmodes
### Title: Enable Use of Strict Mode Checking
### Description:

```
SSHs StrictModes option checks file and ownership permissions in
the user's home directory .ssh folder before accepting login. If world-
writable permissions are found, logon is rejected.

The default SSH configuration has StrictModes enabled. The appropriate
configuration is used if no value is set for StrictModes.

To explicitly enable StrictModes in SSH, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

StrictModes yes
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_enable\_warning\_banner
### Title: Enable SSH Warning Banner
### Description:

```
To enable the warning banner and ensure it is consistent
across the system, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

Banner /etc/issue
Another section contains information on how to create an
appropriate system-wide warning banner.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_enable\_warning\_banner\_net
### Title: Enable SSH Warning Banner
### Description:

```
To enable the warning banner and ensure it is consistent
across the system, add or correct the following line in

/etc/ssh/sshd_config:

Banner /etc/issue.net
Another section contains information on how to create an
appropriate system-wide warning banner.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_enable\_x11\_forwarding
### Title: Enable Encrypted X11 Forwarding
### Description:

```
By default, remote X11 connections are not encrypted when initiated
by users. SSH has the capability to encrypt remote X11 connections when SSH's
X11Forwarding option is enabled.

To enable X11 Forwarding, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

X11Forwarding yes
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_limit\_user\_access
### Title: Limit Users' SSH Access
### Description:

```
By default, the SSH configuration allows any user with an account
to access the system. There are several options available to limit
which users and group can access the system via SSH. It is
recommended that at least one of the following options be leveraged:
- AllowUsers variable gives the system administrator the option of
  allowing specific users to ssh into the system. The list consists of
  space separated user names. Numeric user IDs are not recognized with
  this variable. If a system administrator wants to restrict user
  access further by specifically allowing a user's access only from a
  particular host, the entry can be specified in the form of user@host.
- AllowGroups variable gives the system administrator the option of
  allowing specific groups of users to ssh into the system. The list
  consists of space separated group names. Numeric group IDs are not
  recognized with this variable.
- DenyUsers variable gives the system administrator the option of
  denying specific users to ssh into the system. The list consists of
  space separated user names. Numeric user IDs are not recognized with
  this variable. If a system administrator wants to restrict user
  access further by specifically denying a user's access from a
  particular host, the entry can be specified in the form of user@host.
- DenyGroups variable gives the system administrator the option of
  denying specific groups of users to ssh into the system. The list
  consists of space separated group names. Numeric group IDs are not
  recognized with this variable.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_print\_last\_log
### Title: Enable SSH Print Last Log
### Description:

```
Ensure that SSH will display the date and time of the last successful account logon.

The default SSH configuration enables print of the date and time of the last login.
The appropriate configuration is used if no value is set for PrintLastLog.

To explicitly enable LastLog in SSH, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

PrintLastLog yes
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_rekey\_limit
### Title: Force frequent session key renegotiation
### Description:

```
The RekeyLimit parameter specifies how often
the session key of the is renegotiated, both in terms of
amount of data that may be transmitted and the time
elapsed.
To decrease the default limits, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

RekeyLimit 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_set\_login\_grace\_time
### Title: Ensure SSH LoginGraceTime is configured
### Description:

```
The LoginGraceTime parameter to the SSH server specifies the time allowed for successful authentication to
the SSH server. The longer the Grace period is the more open unauthenticated connections
can exist. Like other session controls in this session the Grace Period should be limited to
appropriate limits to ensure the service is available for needed access.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_set\_loglevel\_info
### Title: Set LogLevel to INFO
### Description:

```
The INFO parameter specifices that record login and logout activity will be logged.

The default SSH configuration sets the log level to INFO. The appropriate
configuration is used if no value is set for LogLevel.

To explicitly specify the log level in SSH, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

LogLevel INFO
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_set\_loglevel\_verbose
### Title: Set SSH Daemon LogLevel to VERBOSE
### Description:

```
The VERBOSE parameter configures the SSH daemon to record login and logout activity.
To specify the log level in
SSH, add or correct the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

LogLevel VERBOSE
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_set\_max\_auth\_tries
### Title: Set SSH authentication attempt limit
### Description:

```
The MaxAuthTries parameter specifies the maximum number of authentication attempts
permitted per connection. Once the number of failures reaches half this value, additional failures are logged.
to set MaxAUthTries edit /etc/ssh/sshd_config as follows:
MaxAuthTries 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_set\_max\_sessions
### Title: Set SSH MaxSessions limit
### Description:

```
The MaxSessions parameter specifies the maximum number of open sessions permitted
from a given connection. To set MaxSessions edit
/etc/ssh/sshd_config as follows: MaxSessions 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_set\_maxstartups
### Title: Ensure SSH MaxStartups is configured
### Description:

```
The MaxStartups parameter specifies the maximum number of concurrent
unauthenticated connections to the SSH daemon. Additional connections will be
dropped until authentication succeeds or the LoginGraceTime expires for a
connection. To confgure MaxStartups, you should add or correct the following
line in the
/etc/ssh/sshd_config file:
MaxStartups 
CIS recommends a MaxStartups value of '10:30:60', or more restrictive where
dictated by site policy.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_use\_approved\_ciphers\_ordered\_stig
### Title: Use Only FIPS 140-2 Validated Ciphers
### Description:

```
Limit the ciphers to those algorithms which are FIPS-approved.
The following line in /etc/ssh/sshd_config
demonstrates use of FIPS-approved ciphers:
Ciphers aes256-ctr,aes256-gcm@openssh.com,aes192-ctr,aes128-ctr,aes128-gcm@openssh.com
If this line does not contain these ciphers in exact order,
is commented out, or is missing, this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_use\_approved\_kex\_ordered\_stig
### Title: Use Only FIPS 140-2 Validated Key Exchange Algorithms
### Description:

```
Limit the key exchange algorithms to those  which are FIPS-approved.
Add or modify the following line in /etc/ssh/sshd_config
KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
This rule ensures that only the key exchange algorithms mentioned
above (or their subset) are configured for use, keeping the given
order of algorithms.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_use\_approved\_macs\_ordered\_stig
### Title: Use Only FIPS 140-2 Validated MACs
### Description:

```
Limit the MACs to those hash algorithms which are FIPS-approved.
The following line in /etc/ssh/sshd_config
demonstrates use of FIPS-approved MACs:
MACs hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com
If this line does not contain these MACs in exact order,
is commented out, or is missing, this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_use\_priv\_separation
### Title: Enable Use of Privilege Separation
### Description:

```
When enabled, SSH will create an unprivileged child process that
has the privilege of the authenticated user. To enable privilege separation in
SSH, add or correct the following line in the /etc/ssh/sshd_config file:
UsePrivilegeSeparation 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_use\_strong\_ciphers
### Title: Use Only Strong Ciphers
### Description:

```
Limit the ciphers to strong algorithms.
Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode.
The following line in /etc/ssh/sshd_config
demonstrates use of those ciphers:
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
The man page sshd_config(5) contains a list of supported ciphers.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_use\_strong\_kex
### Title: Use Only Strong Key Exchange algorithms
### Description:

```
Limit the Key Exchange to strong algorithms.
The following line in /etc/ssh/sshd_config demonstrates use
of those:
KexAlgorithms 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_use\_strong\_macs
### Title: Use Only Strong MACs
### Description:

```
Limit the MACs to strong hash algorithms.
The following line in /etc/ssh/sshd_config demonstrates use
of those MACs:

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_x11\_use\_localhost
### Title: Prevent remote hosts from connecting to the proxy display
### Description:

```
The SSH daemon should prevent remote hosts from connecting to the proxy
display.

The default SSH configuration for X11UseLocalhost is yes,
which prevents remote hosts from connecting to the proxy display.

To explicitly prevent remote connections to the proxy display, add or correct
the following line in


/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf:

X11UseLocalhost yes
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sssd\_offline\_cred\_expiration
### Title: Configure SSSD to Expire Offline Credentials
### Description:

```
SSSD should be configured to expire offline credentials after 1 day.

To configure SSSD to expire offline credentials, set
offline_credentials_expiration to 1 under the [pam]
section in /etc/sssd/sssd.conf. For example:
[pam]
offline_credentials_expiration = 1

```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_xorg-x11-server-common\_removed
### Title: Remove the X Windows Package Group
### Description:

```
By removing the xorg-x11-server-common package, the system no longer has X Windows
installed. If X Windows is not installed then the system cannot boot into graphical user mode.
This prevents the system from being accidentally or maliciously booted into a graphical.target
mode. To do so, run the following command:
$ sudo apt_get groupremove "X Window System"
$ sudo apt_get remove xorg-x11-server-common
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_audit-audispd-plugins\_installed
### Title: Ensure the default plugins for the audit dispatcher are Installed
### Description:

```
The audit-audispd-plugins package should be installed.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_audit\_installed
### Title: Ensure the audit Subsystem is Installed
### Description:

```
The audit package should be installed.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_auditd\_enabled
### Title: Enable auditd Service
### Description:

```
The auditd service is an essential userspace component of
the Linux Auditing System, as it is responsible for writing audit records to
disk.

The auditd service can be enabled with the following command:
$ sudo systemctl enable auditd.service
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_audit\_argument
### Title: Enable Auditing for Processes Which Start Prior to the Audit Daemon
### Description:

```
To ensure all processes can be audited, even those which start
prior to the audit daemon, add the argument audit=1 to the default
GRUB 2 command line for the Linux operating system.
To ensure that audit=1 is added as a kernel command line
argument to newly installed kernels, add audit=1 to the
default Grub2 command line for Linux operating systems. Modify the line within
/etc/default/grub as shown below:
GRUB_CMDLINE_LINUX="... audit=1 ..."
Run the following command to update command line for already installed kernels:# update-grub
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_grub2\_audit\_backlog\_limit\_argument
### Title: Extend Audit Backlog Limit for the Audit Daemon
### Description:

```
To improve the kernel capacity to queue all log events, even those which occurred
prior to the audit daemon, add the argument audit_backlog_limit=8192 to the default
GRUB 2 command line for the Linux operating system.
To ensure that audit_backlog_limit=8192 is added as a kernel command line
argument to newly installed kernels, add audit_backlog_limit=8192 to the
default Grub2 command line for Linux operating systems. Modify the line within
/etc/default/grub as shown below:
GRUB_CMDLINE_LINUX="... audit_backlog_limit=8192 ..."
Run the following command to update command line for already installed kernels:# update-grub
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_immutable
### Title: Make the auditd Configuration Immutable
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d in order to make the auditd configuration
immutable:
-e 2
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file in order to make the auditd configuration
immutable:
-e 2
With this setting, a reboot will be required to change any audit rules.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_mac\_modification
### Title: Record Events that Modify the System's Mandatory Access Controls
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:

-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_mac\_modification\_usr\_share
### Title: Record Events that Modify the System's Mandatory Access Controls in usr/share
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d:
-w /usr/share/selinux/ -p wa -k MAC-policy
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-w /usr/share/selinux/ -p wa -k MAC-policy
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_media\_export
### Title: Ensure auditd Collects Information on Exporting to Media (successful)
### Description:

```
At a minimum, the audit system should collect media exportation
events for all users and root. If the auditd daemon is configured to
use the augenrules program to read audit rules during daemon startup
(the default), add the following line to a file with suffix .rules in
the directory /etc/audit/rules.d, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S mount -F auid>=1000 -F auid!=unset -F key=export
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S mount -F auid>=1000 -F auid!=unset -F key=export
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_networkconfig\_modification
### Title: Record Events that Modify the System's Network Environment
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/networks -p wa -k audit_rules_networkconfig_modification
-w /etc/network/ -p wa -k audit_rules_networkconfig_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/networks -p wa -k audit_rules_networkconfig_modification
-w /etc/network/ -p wa -k audit_rules_networkconfig_modification
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_session\_events
### Title: Record Attempts to Alter Process and Session Initiation Information
### Description:

```
The audit system already collects process information for all
users and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d in order to watch for attempted manual
edits of files involved in storing such process information:
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file in order to watch for attempted manual
edits of files involved in storing such process information:
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_session\_events\_btmp
### Title: Record Attempts to Alter Process and Session Initiation Information btmp
### Description:

```
The audit system already collects process information for all
users and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d in order to watch for attempted manual
edits of files involved in storing such process information:
-w /var/log/btmp -p wa -k session
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file in order to watch for attempted manual
edits of files involved in storing such process information:
-w /var/log/btmp -p wa -k session
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_session\_events\_utmp
### Title: Record Attempts to Alter Process and Session Initiation Information utmp
### Description:

```
The audit system already collects process information for all
users and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d in order to watch for attempted manual
edits of files involved in storing such process information:
-w /run/utmp -p wa -k session
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file in order to watch for attempted manual
edits of files involved in storing such process information:
-w /run/utmp -p wa -k session
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_session\_events\_wtmp
### Title: Record Attempts to Alter Process and Session Initiation Information wtmp
### Description:

```
The audit system already collects process information for all
users and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d in order to watch for attempted manual
edits of files involved in storing such process information:
 -w /var/log/wtmp -p wa -k session
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file in order to watch for attempted manual
edits of files involved in storing such process information:
 -w /var/log/wtmp -p wa -k session
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_sudoers
### Title: Ensure auditd Collects System Administrator Actions - /etc/sudoers
### Description:

```
At a minimum, the audit system should collect administrator actions
for all users and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the default),
add the following line to a file with suffix .rules in the directory
/etc/audit/rules.d:
-w /etc/sudoers -p wa -k actions
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-w /etc/sudoers -p wa -k actions
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_sudoers\_d
### Title: Ensure auditd Collects System Administrator Actions - /etc/sudoers.d/
### Description:

```
At a minimum, the audit system should collect administrator actions
for all users and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the default),
add the following line to a file with suffix .rules in the directory
/etc/audit/rules.d:
-w /etc/sudoers.d/ -p wa -k actions
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-w /etc/sudoers.d/ -p wa -k actions
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_suid\_privilege\_function
### Title: Record Events When Privileged Executables Are Run
### Description:

```
Verify the system generates an audit record when privileged functions are executed.

If audit is using the "auditctl" tool to load the rules, run the following command:

$ sudo grep execve /etc/audit/audit.rules

If audit is using the "augenrules" tool to load the rules, run the following command:

$ sudo grep -r execve /etc/audit/rules.d


-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid


If both the "b32" and "b64" audit rules for "SUID" files are not defined, this is a finding.
If both the "b32" and "b64" audit rules for "SGID" files are not defined, this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_sysadmin\_actions
### Title: Ensure auditd Collects System Administrator Actions
### Description:

```
At a minimum, the audit system should collect administrator actions
for all users and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the default),
add the following line to a file with suffix .rules in the directory
/etc/audit/rules.d:
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification
### Title: Record Events that Modify User/Group Information
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d, in order to capture events that modify
account changes:
-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file, in order to capture events that modify
account changes:
-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_group
### Title: Record Events that Modify User/Group Information - /etc/group
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d, in order to capture events that modify
account changes:

-w /etc/group -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file, in order to capture events that modify
account changes:

-w /etc/group -p wa -k audit_rules_usergroup_modification
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_gshadow
### Title: Record Events that Modify User/Group Information - /etc/gshadow
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d, in order to capture events that modify
account changes:

-w /etc/gshadow -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file, in order to capture events that modify
account changes:

-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_opasswd
### Title: Record Events that Modify User/Group Information - /etc/security/opasswd
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d, in order to capture events that modify
account changes:

-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file, in order to capture events that modify
account changes:

-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_passwd
### Title: Record Events that Modify User/Group Information - /etc/passwd
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d, in order to capture events that modify
account changes:

-w /etc/passwd -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file, in order to capture events that modify
account changes:

-w /etc/passwd -p wa -k audit_rules_usergroup_modification
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_shadow
### Title: Record Events that Modify User/Group Information - /etc/shadow
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d, in order to capture events that modify
account changes:

-w /etc/shadow -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file, in order to capture events that modify
account changes:

-w /etc/shadow -p wa -k audit_rules_usergroup_modification
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_var\_log\_journal
### Title: Ensure auditd Collects records for events that affect "/var/log/journal"
### Description:

```
Auditing the systemd journal files provides logging that can be used for
forensic purposes. Verify the system generates audit records for all events
that affect "/var/log/journal" by using the following command:


$ sudo auditctl -l | grep journal
-w /var/log/journal/ -p wa -k systemd_journal


If the command does not return a line that matches the example or the line
is commented out, this is a finding.

Note: The "-k" value is arbitrary and can be different from the example
output above.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_sudo\_log\_events
### Title: Record Attempts to perform maintenance activities
### Description:

```
The Ubuntu 22.04 operating system must generate audit records for
privileged activities, nonlocal maintenance, diagnostic sessions and
other system-level access.

Verify the operating system audits activities performed during nonlocal
maintenance and diagnostic sessions. Run the following command:
$ sudo auditctl -l | grep sudo.log
-w /var/log/sudo.log -p wa -k maintenance
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_directory\_access\_var\_log\_audit
### Title: Record Access Events to Audit Log Directory
### Description:

```
The audit system should collect access events to read audit log directory.
The following audit rule will assure that access to audit log directory are
collected.
-a always,exit -F dir=/var/log/audit/ -F perm=r -F auid>=1000 -F auid!=unset -F key=access-audit-trail
If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
rule to a file with suffix .rules in the directory
/etc/audit/rules.d.
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the rule to
/etc/audit/audit.rules file.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_directory\_permissions\_var\_log\_audit
### Title: System Audit Logs Must Have Mode 0750 or Less Permissive
### Description:

```
If log_group in /etc/audit/auditd.conf is set to a group other than the root
group account, change the mode of the audit log files with the following command:
$ sudo chmod 0750 /var/log/audit

Otherwise, change the mode of the audit log files with the following command:
$ sudo chmod 0700 /var/log/audit
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_group\_ownership\_var\_log\_audit
### Title: System Audit Logs Must Be Group Owned By Root
### Description:

```
All audit logs must be group owned by root user. The path for audit log can
be configured via log_file parameter in /etc/audit/auditd.conf
or, by default, the path for audit log is /var/log/audit/.

To properly set the group owner of /var/log/audit/*, run the command:
$ sudo chgrp root /var/log/audit/*

If log_group in /etc/audit/auditd.conf is set to a group other
than the root group account, change the group ownership of the audit logs
to this specific group.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_group\_ownership\_var\_log\_audit\_stig
### Title: System Audit Logs Must Be Group Owned By Root
### Description:

```
All audit logs must be group owned by root user.

Determine where the audit logs are stored with the following command:
$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, determine if the audit log files
are owned by the "root" group by using the following command:
$ sudo stat -c "%n %G" /var/log/audit/*
/var/log/audit/audit.log root
If the audit log files are owned by a group other than "root", this is a finding.

To remediate, configure the audit log directory and its underlying files to be owned by "root"
group.

Set the "log_group" parameter of the audit configuration file to the "root" value so when a
new log file is created, its group owner is properly set:
$ sudo sed -i '/^log_group/D' /etc/audit/auditd.conf
$ sudo sed -i /^log_file/a'log_group = root' /etc/audit/auditd.conf

Last, signal the audit daemon to reload the configuration file to update the group owners
of existing files:
$ sudo systemctl kill auditd -s SIGHUP
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownership\_audit\_configuration
### Title: Audit Configuration Files Must Be Owned By Group root
### Description:

```
All audit configuration files must be owned by group root.
chown :root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownership\_audit\_configuration
### Title: Audit Configuration Files Must Be Owned By Root
### Description:

```
All audit configuration files must be owned by root user.

To properly set the owner of /etc/audit/, run the command:
$ sudo chown root /etc/audit/ 

To properly set the owner of /etc/audit/rules.d/, run the command:
$ sudo chown root /etc/audit/rules.d/ 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownership\_var\_log\_audit
### Title: System Audit Logs Must Be Owned By Root
### Description:

```
All audit logs must be owned by root user and group. By default, the path for audit log is /var/log/audit/.

To properly set the owner of /var/log/audit, run the command:
$ sudo chown root /var/log/audit 

To properly set the owner of /var/log/audit/*, run the command:
$ sudo chown root /var/log/audit/* 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownership\_var\_log\_audit\_stig
### Title: System Audit Logs Must Be Owned By Root
### Description:

```
All audit logs must be owned by root user. The path for audit log can be
configured via log_file parameter in /etc/audit/auditd.conf
or by default, the path for audit log is /var/log/audit/.

To properly set the owner of /var/log/audit/*, run the command:
$ sudo chown root /var/log/audit/* 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_audit
### Title: System Audit Logs Must Have Mode 0640 or Less Permissive
### Description:

```
If log_group in /etc/audit/auditd.conf is set to a group other than the
root
group account, change the mode of the audit log files with the following command:
$ sudo chmod 0640 

Otherwise, change the mode of the audit log files with the following command:
$ sudo chmod 0600 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_audit\_stig
### Title: System Audit Logs Must Have Mode 0600 or Less Permissive
### Description:

```
Determine where the audit logs are stored with the following command:
$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, determine
if the audit log files have a mode of "600" or less by using the following command:
$ sudo stat -c "%n %a" /var/log/audit/*
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_chmod
### Title: Record Events that Modify the System's Discretionary Access Controls - chmod
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured to
use the augenrules program to read audit rules during daemon startup
(the default), add the following line to a file with suffix .rules in
the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_chown
### Title: Record Events that Modify the System's Discretionary Access Controls - chown
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured to
use the augenrules program to read audit rules during daemon startup
(the default), add the following line to a file with suffix .rules in
the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_fchmod
### Title: Record Events that Modify the System's Discretionary Access Controls - fchmod
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured to
use the augenrules program to read audit rules during daemon startup
(the default), add the following line to a file with suffix .rules in
the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_fchmodat
### Title: Record Events that Modify the System's Discretionary Access Controls - fchmodat
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured to
use the augenrules program to read audit rules during daemon startup
(the default), add the following line to a file with suffix .rules in
the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_fchown
### Title: Record Events that Modify the System's Discretionary Access Controls - fchown
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_fchownat
### Title: Record Events that Modify the System's Discretionary Access Controls - fchownat
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_fremovexattr
### Title: Record Events that Modify the System's Discretionary Access Controls - fremovexattr
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root.

If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid=0 -F key=perm_mod

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -F key=perm_mod

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid=0 -F key=perm_mod

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_fsetxattr
### Title: Record Events that Modify the System's Discretionary Access Controls - fsetxattr
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_lchown
### Title: Record Events that Modify the System's Discretionary Access Controls - lchown
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_lremovexattr
### Title: Record Events that Modify the System's Discretionary Access Controls - lremovexattr
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root.

If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -F key=perm_mod

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -F key=perm_mod

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -F key=perm_mod

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_lsetxattr
### Title: Record Events that Modify the System's Discretionary Access Controls - lsetxattr
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_removexattr
### Title: Record Events that Modify the System's Discretionary Access Controls - removexattr
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following line to a file with suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid=0 -F key=perm_mod

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid=0 -F key=perm_mod

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid=0 -F key=perm_mod

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid=0 -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_setxattr
### Title: Record Events that Modify the System's Discretionary Access Controls - setxattr
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid=0 -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid=0 -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid=0 -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid=0 -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_umount
### Title: Record Events that Modify the System's Discretionary Access Controls - umount
### Description:

```
At a minimum, the audit system should collect file system umount
changes. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=unset -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_dac\_modification\_umount2
### Title: Record Events that Modify the System's Discretionary Access Controls - umount2
### Description:

```
At a minimum, the audit system should collect file system umount2
changes. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=unset -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_execution\_chacl
### Title: Record Any Attempts to Run chacl
### Description:

```
At a minimum, the audit system should collect any execution attempt
of the chacl command for all users and root. If the auditd
daemon is configured to use the augenrules program to read audit rules
during daemon startup (the default), add the following lines to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file:
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_execution\_setfacl
### Title: Record Any Attempts to Run setfacl
### Description:

```
At a minimum, the audit system should collect any execution attempt
of the setfacl command for all users and root. If the auditd
daemon is configured to use the augenrules program to read audit rules
during daemon startup (the default), add the following lines to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file:
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_execution\_chcon
### Title: Record Any Attempts to Run chcon
### Description:

```
At a minimum, the audit system should collect any execution attempt
of the chcon command for all users and root. If the auditd
daemon is configured to use the augenrules program to read audit rules
during daemon startup (the default), add the following lines to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file:
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_file\_deletion\_events\_rename
### Title: Ensure auditd Collects File Deletion Events by User - rename
### Description:

```
At a minimum, the audit system should collect file deletion events
for all users and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S rename -F auid>=1000 -F auid!=unset -F key=delete
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S rename -F auid>=1000 -F auid!=unset -F key=delete
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_file\_deletion\_events\_renameat
### Title: Ensure auditd Collects File Deletion Events by User - renameat
### Description:

```
At a minimum, the audit system should collect file deletion events
for all users and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S renameat -F auid>=1000 -F auid!=unset -F key=delete
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S renameat -F auid>=1000 -F auid!=unset -F key=delete
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_file\_deletion\_events\_rmdir
### Title: Ensure auditd Collects File Deletion Events by User - rmdir
### Description:

```
At a minimum, the audit system should collect file deletion events
for all users and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S rmdir -F auid>=1000 -F auid!=unset -F key=delete
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S rmdir -F auid>=1000 -F auid!=unset -F key=delete
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_file\_deletion\_events\_unlink
### Title: Ensure auditd Collects File Deletion Events by User - unlink
### Description:

```
At a minimum, the audit system should collect file deletion events
for all users and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S unlink -F auid>=1000 -F auid!=unset -F key=delete
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S unlink -F auid>=1000 -F auid!=unset -F key=delete
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_file\_deletion\_events\_unlinkat
### Title: Ensure auditd Collects File Deletion Events by User - unlinkat
### Description:

```
At a minimum, the audit system should collect file deletion events
for all users and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_unsuccessful\_file\_modification\_creat
### Title: Record Unsuccessful Access Attempts to Files - creat
### Description:

```
At a minimum, the audit system should collect unauthorized file
accesses for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following lines to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
If the system is 64 bit then also add the following lines:

-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
If the system is 64 bit then also add the following lines:

-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_unsuccessful\_file\_modification\_ftruncate
### Title: Record Unsuccessful Access Attempts to Files - ftruncate
### Description:

```
At a minimum, the audit system should collect unauthorized file
accesses for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following lines to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access

If the system is 64 bit then also add the following lines:

-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access

If the system is 64 bit then also add the following lines:

-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_unsuccessful\_file\_modification\_open
### Title: Record Unsuccessful Access Attempts to Files - open
### Description:

```
At a minimum, the audit system should collect unauthorized file
accesses for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following lines to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access

If the system is 64 bit then also add the following lines:

-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access

If the system is 64 bit then also add the following lines:

-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_unsuccessful\_file\_modification\_open\_by\_handle\_at
### Title: Record Unsuccessful Access Attempts to Files - open\_by\_handle\_at
### Description:

```
At a minimum, the audit system should collect unauthorized file
accesses for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following lines to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
If the system is 64 bit then also add the following lines:

-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
If the system is 64 bit then also add the following lines:

-a always,exit -F arch=b64 -S open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_unsuccessful\_file\_modification\_openat
### Title: Record Unsuccessful Access Attempts to Files - openat
### Description:

```
At a minimum, the audit system should collect unauthorized file
accesses for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following lines to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access

If the system is 64 bit then also add the following lines:

-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access

If the system is 64 bit then also add the following lines:

-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_unsuccessful\_file\_modification\_truncate
### Title: Record Unsuccessful Access Attempts to Files - truncate
### Description:

```
At a minimum, the audit system should collect unauthorized file
accesses for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following lines to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access

If the system is 64 bit then also add the following lines:

-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access

If the system is 64 bit then also add the following lines:

-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_kernel\_module\_loading\_delete
### Title: Ensure auditd Collects Information on Kernel Module Unloading - delete\_module
### Description:

```
To capture kernel module unloading events, use following line, setting ARCH to
either b32 for 32-bit system, or having two lines for both b32 and b64 in case your system is 64-bit:

-a always,exit -F arch=


Place to add the line depends on a way auditd daemon is configured. If it is configured
to use the augenrules program (the default), add the line to a file with suffix
.rules in the directory /etc/audit/rules.d.

If the auditd daemon is configured to use the auditctl utility,
add the line to file /etc/audit/audit.rules.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_kernel\_module\_loading\_finit
### Title: Ensure auditd Collects Information on Kernel Module Loading and Unloading - finit\_module
### Description:

```
If the auditd daemon is configured to use the augenrules program
to read audit rules during daemon startup (the default), add the following lines to a file
with suffix .rules in the directory /etc/audit/rules.d to capture kernel module
loading and unloading events, setting ARCH to either b32 or b64 as appropriate for your system:

-a always,exit -F arch=
    If the auditd daemon is configured to use the auditctl utility to read audit
rules during daemon startup, add the following lines to /etc/audit/audit.rules file
in order to capture kernel module loading and unloading events, setting ARCH to either b32 or
b64 as appropriate for your system:

-a always,exit -F arch=
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_kernel\_module\_loading\_init
### Title: Ensure auditd Collects Information on Kernel Module Loading - init\_module
### Description:

```
To capture kernel module loading events, use following line, setting ARCH to
either b32 for 32-bit system, or having two lines for both b32 and b64 in case your system is 64-bit:

-a always,exit -F arch=


Place to add the line depends on a way auditd daemon is configured. If it is configured
to use the augenrules program (the default), add the line to a file with suffix
.rules in the directory /etc/audit/rules.d.

If the auditd daemon is configured to use the auditctl utility,
add the line to file /etc/audit/audit.rules.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_login\_events\_faillog
### Title: Record Attempts to Alter Logon and Logout Events - faillog
### Description:

```
The audit system already collects login information for all users
and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d in order to watch for attempted manual
edits of files involved in storing logon events:
-w /var/log/faillog -p wa -k logins
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file in order to watch for unattempted manual
edits of files involved in storing logon events:
-w /var/log/faillog -p wa -k logins
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_login\_events\_lastlog
### Title: Record Attempts to Alter Logon and Logout Events - lastlog
### Description:

```
The audit system already collects login information for all users
and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d in order to watch for attempted manual
edits of files involved in storing logon events:
-w /var/log/lastlog -p wa -k logins
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file in order to watch for unattempted manual
edits of files involved in storing logon events:
-w /var/log/lastlog -p wa -k logins
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_login\_events\_tallylog
### Title: Record Attempts to Alter Logon and Logout Events - tallylog
### Description:

```
The audit system already collects login information for all users
and root. If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d in order to watch for attempted manual
edits of files involved in storing logon events:
-w /var/log/tallylog -p wa -k logins
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file in order to watch for unattempted manual
edits of files involved in storing logon events:
-w /var/log/tallylog -p wa -k logins
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_privileged\_commands\_init
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - init
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/init -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/init -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_privileged\_commands\_poweroff
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - poweroff
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/poweroff -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/poweroff -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_privileged\_commands\_reboot
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - reboot
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/reboot -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/reboot -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_privileged\_commands\_shutdown
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - shutdown
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/shutdown -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/shutdown -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands
### Title: Ensure auditd Collects Information on the Use of Privileged Commands
### Description:

```
The audit system should collect information about usage of privileged
commands for all users and root. To find the relevant setuid /
setgid programs, run the following command for each local partition
PART:
$ sudo find 
If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add a line of
the following form to a file with suffix .rules in the directory
/etc/audit/rules.d for each setuid / setgid program on the system,
replacing the SETUID_PROG_PATH part with the full path of that setuid /
setgid program in the list:
-a always,exit -F path=
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules for each setuid / setgid program on the
system, replacing the SETUID_PROG_PATH part with the full path of that
setuid / setgid program in the list:
-a always,exit -F path=
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_apparmor\_parser
### Title: Record Any Attempts to Run apparmor\_parser
### Description:

```
At a minimum, the audit system should collect any execution attempt
of the apparmor_parser command for all users and root. If
the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:
-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following
lines to /etc/audit/audit.rules file:
-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_at
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - at
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_chage
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - chage
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_chfn
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - chfn
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_chsh
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - chsh
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_crontab
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - crontab
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_fdisk
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - fdisk
### Description:

```
Configure the operating system to audit the execution of the partition
management program "fdisk".
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_gpasswd
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - gpasswd
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_insmod
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - insmod
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-w /sbin/insmod -p x -k modules
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_kmod
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - kmod
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-w /bin/kmod -p x -k modules
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-w /bin/kmod -p x -k modules
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_modprobe
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - modprobe
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-w /sbin/modprobe -p x -k modules
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-w /sbin/modprobe -p x -k modules
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_mount
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - mount
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_newgidmap
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - newgidmap
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/newgidmap -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/newgidmap -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_newgrp
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - newgrp
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_newuidmap
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - newuidmap
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/newuidmap -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/newuidmap -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_pam\_timestamp\_check
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - pam\_timestamp\_check
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/pam_timestamp_check
-F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/pam_timestamp_check
-F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_passwd
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - passwd
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_postdrop
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - postdrop
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_postqueue
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - postqueue
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_rmmod
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - rmmod
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-w /sbin/rmmod -p x -k modules
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_ssh\_agent
### Title: Record Any Attempts to Run ssh-agent
### Description:

```
At a minimum, the audit system should collect any execution attempt
of the ssh-agent command for all users and root. If the auditd
daemon is configured to use the augenrules program to read audit rules
during daemon startup (the default), add the following lines to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh-agent
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file:
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh-agent
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_ssh\_keysign
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - ssh-keysign
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_su
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - su
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_sudo
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - sudo
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_sudoedit
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - sudoedit
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_umount
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - umount
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_unix\_chkpwd
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - unix\_chkpwd
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_unix\_update
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - unix\_update
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_usermod
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - usermod
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_time\_adjtimex
### Title: Record attempts to alter time through adjtimex
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S adjtimex -F key=audit_time_rules
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S adjtimex -F key=audit_time_rules
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S adjtimex -F key=audit_time_rules
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S adjtimex -F key=audit_time_rules
The -k option allows for the specification of a key in string form that can be
used for better reporting capability through ausearch and aureport. Multiple
system calls can be defined on the same line to save space if desired, but is
not required. See an example of multiple combined syscalls:
-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=audit_time_rules
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_time\_clock\_settime
### Title: Record Attempts to Alter Time Through clock\_settime
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change
The -k option allows for the specification of a key in string form that can
be used for better reporting capability through ausearch and aureport.
Multiple system calls can be defined on the same line to save space if
desired, but is not required. See an example of multiple combined syscalls:
-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=audit_time_rules
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_time\_settimeofday
### Title: Record attempts to alter time through settimeofday
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S settimeofday -F key=audit_time_rules
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S settimeofday -F key=audit_time_rules
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S settimeofday -F key=audit_time_rules
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S settimeofday -F key=audit_time_rules
The -k option allows for the specification of a key in string form that can be
used for better reporting capability through ausearch and aureport. Multiple
system calls can be defined on the same line to save space if desired, but is
not required. See an example of multiple combined syscalls:
-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=audit_time_rules
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_time\_stime
### Title: Record Attempts to Alter Time Through stime
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d for both 32 bit and 64 bit systems:
-a always,exit -F arch=b32 -S stime -F key=audit_time_rules
Since the 64 bit version of the "stime" system call is not defined in the audit
lookup table, the corresponding "-F arch=b64" form of this rule is not expected
to be defined on 64 bit systems (the aforementioned "-F arch=b32" stime rule
form itself is sufficient for both 32 bit and 64 bit systems). If the
auditd daemon is configured to use the auditctl utility to
read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file for both 32 bit and 64 bit systems:
-a always,exit -F arch=b32 -S stime -F key=audit_time_rules
Since the 64 bit version of the "stime" system call is not defined in the audit
lookup table, the corresponding "-F arch=b64" form of this rule is not expected
to be defined on 64 bit systems (the aforementioned "-F arch=b32" stime rule
form itself is sufficient for both 32 bit and 64 bit systems). The -k option
allows for the specification of a key in string form that can be used for
better reporting capability through ausearch and aureport. Multiple system
calls can be defined on the same line to save space if desired, but is not
required. See an example of multiple combined system calls:
-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=audit_time_rules
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_time\_watch\_localtime
### Title: Record Attempts to Alter the localtime File
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the default),
add the following line to a file with suffix .rules in the directory
/etc/audit/rules.d:
-w /etc/localtime -p wa -k audit_time_rules
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-w /etc/localtime -p wa -k audit_time_rules
The -k option allows for the specification of a key in string form that can
be used for better reporting capability through ausearch and aureport and
should always be used.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_audispd\_configure\_remote\_server
### Title: Configure audispd Plugin To Send Logs To Remote Server
### Description:

```
Configure the audispd plugin to off-load audit records onto a different
system or media from the system being audited.

First, set the active option in
/etc/audisp/plugins.d/au-remote.conf

Set the remote_server option in /etc/audit/audisp-remote.conf
with an IP address or hostname of the system that the audispd plugin should
send audit records to. For example
remote_server = 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_audispd\_configure\_sufficiently\_large\_partition
### Title: Configure a Sufficiently Large Partition for Audit Logs
### Description:

```
The Ubuntu 22.04 operating system must allocate audit record storage
capacity to store at least one weeks worth of audit records when audit
records are not immediately sent to a central audit record storage
facility.

The partition size needed to capture a week's worth of audit records is
based on the activity level of the system and the total storage capacity
available.


Determine which partition the audit records are being written to with the
following command:

$ sudo grep log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Check the size of the partition that audit records are written to with the
following command:

$ sudo df -h /var/log/audit/
/dev/sda2 24G 10.4G 13.6G 43% /var/log/audit
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_audispd\_syslog\_plugin\_activated
### Title: Configure auditd to use audispd's syslog plugin
### Description:

```
To configure the auditd service to use the
syslog plug-in of the audispd audit event multiplexor, set
the active line in /etc/audit/plugins.d/syslog.conf to yes.
Restart the auditd service:
$ sudo service auditd restart
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_disk\_error\_action
### Title: Configure auditd Disk Error Action on Disk Error
### Description:

```
The auditd service can be configured to take an action
when there is a disk error.
Edit the file /etc/audit/auditd.conf. Add or modify the following line,
substituting ACTION appropriately:
disk_error_action = 
Set this value to single to cause the system to switch to single-user
mode for corrective action. Acceptable values also include syslog,
exec, single, and halt. For certain systems, the need for availability
outweighs the need to log all actions, and a different setting should be
determined. Details regarding all possible values for ACTION are described in the
auditd.conf man page.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_disk\_error\_action\_stig
### Title: Configure auditd Disk Error Action on Disk Error
### Description:

```
The auditd service can be configured to take an action
when there is a disk error.
Edit the file /etc/audit/auditd.conf. Add or modify the following line,
substituting ACTION appropriately:
disk_error_action = 
Set this value to single to cause the system to switch to single-user
mode for corrective action. Acceptable values also include syslog,
exec, single, and halt. For certain systems, the need for availability
outweighs the need to log all actions, and a different setting should be
determined. Details regarding all possible values for ACTION are described in the
auditd.conf man page.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_disk\_full\_action
### Title: Configure auditd Disk Full Action when Disk Space Is Full
### Description:

```
The auditd service can be configured to take an action
when disk space is running low but prior to running out of space completely.
Edit the file /etc/audit/auditd.conf. Add or modify the following line,
substituting ACTION appropriately:
disk_full_action = 
Set this value to single to cause the system to switch to single-user
mode for corrective action. Acceptable values also include syslog,

exec,

single, and halt. For certain systems, the need for availability
outweighs the need to log all actions, and a different setting should be
determined. Details regarding all possible values for ACTION are described in the
auditd.conf man page.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_disk\_full\_action\_stig
### Title: Configure auditd Disk Full Action when Disk Space Is Full
### Description:

```
The auditd service can be configured to take an action
when disk space is running low but prior to running out of space completely.
Edit the file /etc/audit/auditd.conf. Add or modify the following line,
substituting ACTION appropriately:
disk_full_action = 
Set this value to single to cause the system to switch to single-user
mode for corrective action. Acceptable values also include syslog,
single, and halt. For certain systems, the need for availability
outweighs the need to log all actions, and a different setting should be
determined. Details regarding all possible values for ACTION are described in the
auditd.conf man page.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_retention\_action\_mail\_acct
### Title: Configure auditd mail\_acct Action on Low Disk Space
### Description:

```
The auditd service can be configured to send email to
a designated account in certain situations. Add or correct the following line
in /etc/audit/auditd.conf to ensure that administrators are notified
via email for those situations:
action_mail_acct = 
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_retention\_admin\_space\_left\_action
### Title: Configure auditd admin\_space\_left Action on Low Disk Space
### Description:

```
The auditd service can be configured to take an action
when disk space is running low but prior to running out of space completely.
Edit the file /etc/audit/auditd.conf. Add or modify the following line,
substituting ACTION appropriately:
admin_space_left_action = 
Set this value to single to cause the system to switch to single user
mode for corrective action. Acceptable values also include suspend and
halt. For certain systems, the need for availability
outweighs the need to log all actions, and a different setting should be
determined. Details regarding all possible values for ACTION are described in the
auditd.conf man page.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_retention\_admin\_space\_left\_percentage
### Title: Configure auditd admin\_space\_left on Low Disk Space
### Description:

```
The auditd service can be configured to take an action
when disk space is running low but prior to running out of space completely.
Edit the file /etc/audit/auditd.conf. Add or modify the following line,
substituting PERCENTAGE appropriately:
admin_space_left = 
Set this value to 
to cause the system to perform an action.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_retention\_max\_log\_file
### Title: Configure auditd Max Log File Size
### Description:

```
Determine the amount of audit data (in megabytes)
which should be retained in each log file. Edit the file
/etc/audit/auditd.conf. Add or modify the following line, substituting
the correct value of  for STOREMB:
max_log_file = 
Set the value to 6 (MB) or higher for general-purpose systems.
Larger values, of course,
support retention of even more audit data.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_retention\_max\_log\_file\_action
### Title: Configure auditd max\_log\_file\_action Upon Reaching Maximum Log Size
### Description:

```
The default action to take when the logs reach their maximum size
is to rotate the log files, discarding the oldest one. To configure the action taken
by auditd, add or correct the line in /etc/audit/auditd.conf:
max_log_file_action = 
Possible values for ACTION are described in the auditd.conf man
page. These include:

Set the  to .
The setting is case-insensitive.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_retention\_max\_log\_file\_action\_stig
### Title: Configure auditd max\_log\_file\_action Upon Reaching Maximum Log Size
### Description:

```
The default action to take when the logs reach their maximum size
is to rotate the log files, discarding the oldest one. To configure the action taken
by auditd, add or correct the line in /etc/audit/auditd.conf:
max_log_file_action = 
Possible values for ACTION are described in the auditd.conf man
page. These include:

Set the  to rotate to ensure log rotation
occurs. This is the default. The setting is case-insensitive.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_retention\_num\_logs
### Title: Configure auditd Number of Logs Retained
### Description:

```
Determine how many log files
auditd should retain when it rotates logs.
Edit the file /etc/audit/auditd.conf. Add or modify the following
line, substituting NUMLOGS with the correct value of :
num_logs = 
Set the value to 5 for general-purpose systems.
Note that values less than 2 result in no log rotation.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_retention\_space\_left
### Title: Configure auditd space\_left on Low Disk Space
### Description:

```
The auditd service can be configured to take an action
when disk space is running low but prior to running out of space completely.
Edit the file /etc/audit/auditd.conf. Add or modify the following line,
substituting SIZE_in_MB appropriately:
space_left = 
Set this value to the appropriate size in Megabytes cause the system to
notify the user of an issue.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_retention\_space\_left\_action
### Title: Configure auditd space\_left Action on Low Disk Space
### Description:

```
The auditd service can be configured to take an action
when disk space starts to run low.
Edit the file /etc/audit/auditd.conf. Modify the following line,
substituting ACTION appropriately:
space_left_action = 
Possible values for ACTION are described in the auditd.conf man page.
These include:

Set this to email (instead of the default,
which is suspend) as it is more likely to get prompt attention. Acceptable values
also include suspend, single, and halt.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_data\_retention\_space\_left\_percentage
### Title: Configure auditd space\_left on Low Disk Space
### Description:

```
The auditd service can be configured to take an action
when disk space is running low but prior to running out of space completely.
Edit the file /etc/audit/auditd.conf. Add or modify the following line,
substituting PERCENTAGE appropriately:
space_left = 
Set this value to at least 25 to cause the system to
notify the user of an issue.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_freq
### Title: Set number of records to cause an explicit flush to audit logs
### Description:

```
To configure Audit daemon to issue an explicit flush to disk command
after writing  records, set freq to 
in /etc/audit/auditd.conf.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_local\_events
### Title: Include Local Events in Audit Logs
### Description:

```
To configure Audit daemon to include local events in Audit logs, set
local_events to yes in /etc/audit/auditd.conf.
This is the default setting.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_log\_format
### Title: Resolve information before writing to audit logs
### Description:

```
To configure Audit daemon to resolve all uid, gid, syscall,
architecture, and socket address information before writing the
events to disk, set log_format to ENRICHED
in /etc/audit/auditd.conf.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_name\_format
### Title: Set hostname as computer node name in audit logs
### Description:

```
To configure Audit daemon to use value returned by gethostname
syscall as computer node name in the audit events,
set name_format to hostname
in /etc/audit/auditd.conf.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_offload\_logs
### Title: Offload audit Logs to External Media
### Description:

```
The operating system must have a crontab script running weekly to
offload audit events of standalone systems.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_overflow\_action
### Title: Appropriate Action Must be Setup When the Internal Audit Event Queue is Full
### Description:

```
The audit system should have an action setup in the event the internal event queue becomes full.
To setup an overflow action edit /etc/audit/auditd.conf. Set overflow_action
to one of the following values: syslog, single, halt.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_write\_logs
### Title: Write Audit Logs to the Disk
### Description:

```
To configure Audit daemon to write Audit logs to the disk, set
write_logs to yes in /etc/audit/auditd.conf.
This is the default setting.
```


# SEE ALSO
**usg**(8)

# COPYRIGHT
Copyright 2025 Canonical Limited. All rights reserved.

The implementation of DISA-STIG rules, CIS rules, profiles, scripts, and other assets are based on the ComplianceAsCode open source project (https://www.open-scap.org/security-policies/scap-security-guide).

ComplianceAsCode's license file can be found in the /usr/share/ubuntu-scap-security-guides/benchmarks directory.
