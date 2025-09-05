% USG-RULES(7) usg-benchmarks 24.04.5
% Eduardo Barretto <eduardo.barretto@canonical.com>
% 05 September 2025

# NAME
usg-rules - usg rules list and description

# LIST OF RULES AND THEIR DESCRIPTIONS
# List of rules
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_aide\_periodic\_checking\_systemd\_timer
### Title: Configure Systemd Timer Execution of AIDE
### Description:

```
At a minimum, AIDE should be configured to run a weekly scan.
To implement a systemd service and a timer unit to run the service periodically:
For example, if a systemd timer is expected to be started every day at 5AM
OnCalendar=*-*-* 05:00:0
          [Timer] section in the timer unit and
a Unit section starting the AIDE check service unit should be referred.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_installed\_OS\_is\_vendor\_supported
### Title: The Installed Operating System Is Vendor Supported
### Description:

```
The installed operating system must be maintained by a vendor.

Red Hat Enterprise Linux is supported by Red Hat, Inc. As the Red Hat Enterprise
Linux vendor, Red Hat, Inc. is responsible for providing security patches.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_encrypt\_partitions
### Title: Encrypt Partitions
### Description:

```
Ubuntu 24.04 natively supports partition encryption through the
Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to
encrypt a partition is during installation time.

        
For manual installations, select the Encrypt checkbox during
partition creation to encrypt the partition. When this
option is selected the system will prompt for a passphrase to use in
decrypting the partition. The passphrase will subsequently need to be entered manually
every time the system boots.


        
Detailed information on encrypting partitions using LUKS or LUKS ciphers can be found on
the Ubuntu 24.04 Documentation web site:
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_banner\_etc\_issue\_cis
### Title: Ensure Local Login Warning Banner Is Configured Properly
### Description:

```
To configure the system local login warning banner edit the /etc/issue file.
The contents of this file is displayed to users prior to login to local terminals.
Replace the default text with a message compliant with the local site policy.
The message should not contain information about operating system version,
release, kernel version or patch level.

The recommended banner text can be tailored in the XCCDF Value xccdf_org.ssgproject.content_value_cis_banner_text:

       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_banner\_etc\_issue\_net\_cis
### Title: Ensure Remote Login Warning Banner Is Configured Properly
### Description:

```
To configure the system remote login warning banner edit the /etc/issue.net file.
The contents of this file is displayed to users prior to login from remote connections.
Replace the default text with a message compliant with the local site policy.
The message should not contain information about operating system version,
release, kernel version or patch level.

The recommended banner text can be tailored in the XCCDF Value xccdf_org.ssgproject.content_value_cis_banner_text:

       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_banner\_etc\_motd\_cis
### Title: Ensure Message Of The Day Is Configured Properly
### Description:

```
To configure the system message of the day banner edit the /etc/motd file.
Replace the default text with a message compliant with the local site policy.
The message should not contain information about operating system version,
release, kernel version or patch level.

The recommended banner text can be tailored in the XCCDF Value xccdf_org.ssgproject.content_value_cis_banner_text:

       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_banner\_etc\_profiled\_ssh\_confirm
### Title: Enable the SSH login confirmation banner
### Description:

```
This rule verifies that that the SSH login confirmation banner is set 
correctly.

The DoD required text is:

        
        if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_nss\_sss\_installed
### Title: Install nss-sss Package
### Description:

```
The libnss-sss package can be installed with the following command:

$ apt-get install libnss-sss
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_pam\_modules\_installed
### Title: Install pam-modules Package
### Description:

```
The libpam-modules package can be installed with the following command:

$ apt-get install libpam-modules
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_pam\_pwquality\_installed
### Title: Install pam\_pwquality Package
### Description:

```
The libpam-pwquality package can be installed with the following command:

$ apt-get install libpam-pwquality
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_pam\_runtime\_installed
### Title: Install pam-runtime Package
### Description:

```
The libpam-runtime package can be installed with the following command:

$ apt-get install libpam-runtime
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_pam\_sss\_installed
### Title: Install pam-sss Package
### Description:

```
The libpam-sss package can be installed with the following command:

$ apt-get install libpam-sss
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_unix\_enabled
### Title: Verify pam\_unix module is activated
### Description:

```
pam_unix is the standard Unix authentication module. It uses standard calls from the
system's libraries to retrieve and set account information as well as authentication.
Usually this is obtained from the /etc/passwd and if shadow is enabled, the
/etc/shadow file as well.

        
The account component performs the task of establishing the status of the user's
account and password based on the following shadow elements: expire,
last_change, max_change, min_change, warn_change. In the case of the latter, it may
offer advice to the user on changing their password or, through the
PAM_AUTHTOKEN_REQD return, delay giving service to the user until they have
established a new password. The entries listed above are documented in the shadow(5)
manual page. Should the user's record not contain one or more of these entries, the
corresponding shadow check is not performed.

        
The authentication component performs the task of checking the users credentials
(password). The default action of this module is to not permit the user access to a
service if their official password is blank.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_display\_login\_attempts
### Title: Ensure PAM Displays Last Logon/Access Notification
### Description:

```
To configure the system to notify users of last logon/access using pam_lastlog,
add or correct the pam_lastlog settings in /etc/pam.d/login
to include showfailed option, such as:
session     required    pam_lastlog.so showfailed
And make sure that the silent option is not set for this specific line.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_pwhistory\_enabled
### Title: Verify pam\_pwhistory module is activated
### Description:

```
The pam_pwhistory.so module is part of the Pluggable Authentication Modules (PAM) 
framework designed to increase password security. It works by storing a history of previously 
used passwords for each user, ensuring users cannot alternate between the same passwords too frequently.

         
This module is incompatible with Kerberos. Furthermore, its usage with NIS or LDAP is 
generally impractical, as other machines can not access local password histories.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_pwhistory\_enforce\_root
### Title: Limit Password Reuse
### Description:

```
Do not allow root to reuse recent passwords. This can be
accomplished by using the enforce_for_root option for the
pam_pwhistory PAM modules.

         
In the file /etc/pam.d/common-password, make sure the parameters
enforce_for_root is present.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_pwhistory\_remember
### Title: Limit Password Reuse
### Description:

```
Do not allow users to reuse recent passwords. This can be
accomplished by using the remember option for the
pam_pwhistory PAM modules.

         
In the file /etc/pam.d/common-password, make sure the parameters
remember and use_authtok are present, and that the value
for the remember parameter is  or greater. For example:
password requisite pam_pwhistory.so 
The DoD STIG requirement is 5 passwords.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_pwhistory\_use\_authtok
### Title: Enforce Password History with use\_authtok
### Description:

```
The use_authtok option ensures the pam_pwhistory module uses the new
password provided by a previously stacked PAM module during password
changes, rather than prompting the user again.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_unix\_authtok
### Title: Require use\_authtok for pam\_unix.so
### Description:

```
When password changing enforce the module to set the new password to the one
provided by a previously stacked password module
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
Ensure that the file /etc/security/faillock.conf contains the following entry:
deny = <count>
Where count should be less than or equal to
 and greater than 0.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_passwords\_pam\_faillock\_enabled
### Title: Ensure pam\_faillock module is enabled
### Description:

```
The pam_faillock.so module maintains a list of failed authentication attempts per
user during a specified interval and locks the account in case there were more than the
configured number of consecutive failed authentications (this is defined by the deny
parameter in the faillock configuration). It stores the failure records into per-user files in
the tally directory.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_passwords\_pam\_faillock\_interval
### Title: Set Interval For Counting Failed Password Attempts
### Description:

```
Utilizing pam_faillock.so, the fail_interval directive configures the system
to lock out an account after a number of incorrect login attempts within a specified time
period.

Ensure that the file /etc/security/faillock.conf contains the following entry:
fail_interval = <interval-in-seconds> where interval-in-seconds is  or greater.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_passwords\_pam\_faillock\_root\_unlock\_time
### Title: Set Root Lockout Time for Failed Password Attempts
### Description:

```
This rule configures the system to lock out root during a specified time period after a
number of incorrect login attempts using pam_faillock.so.

Ensure that the file /etc/security/faillock.conf contains the following entry:
root_unlock_time=<interval-in-seconds> where
interval-in-seconds is  or greater.

If root_unlock_time is set to 0, it may enable attacker to
apply denial of service to legitimate users.
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

Ensure that the file /etc/security/faillock.conf contains the following entry:
unlock_time=<interval-in-seconds> where
interval-in-seconds is  or greater.

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

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_enforce\_root
### Title: Ensure PAM Enforces Password Requirements - Enforce for root User
### Description:

```
The pam_pwquality module's enforce_for_root parameter controls requirements for
enforcing password complexity for the root user. Enable the enforce_for_root
setting in /etc/security/pwquality.conf to require the root user
to use complex passwords.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_maxrepeat
### Title: Set Password Maximum Consecutive Repeating Characters
### Description:

```
The pam_pwquality module's maxrepeat parameter controls requirements for
consecutive repeating characters. When set to a positive number, it will reject passwords
which contain more than that number of consecutive characters. Modify the maxrepeat setting
in /etc/security/pwquality.conf to equal  to prevent a
run of ( + 1) or more identical characters.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_maxsequence
### Title: Limit the maximum number of sequential characters in passwords
### Description:

```
The pwquality maxsequence setting defines the maximum allowable length for consecutive 
character sequences in a new password. Such sequences can be, e.g., 123 or abc. If the value is 
set to 0, this check will be turned off.

          
Note: Passwords that consist mainly of such sequences are unlikely to meet the simplicity criteria 
unless the sequence constitutes only a small portion of the overall password.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_pwquality\_enabled
### Title: Verify pam\_pwquality module is activated
### Description:

```
The pam_pwquality.so module ensures password quality by evaluating user-created passwords 
against a system dictionary and a set of rules designed to detect weak choices. Originally derived 
from the pam_cracklib module, this module is backward-compatible with options of pam_cracklib.

          
The module's process includes prompting the user for a password, checking its strength, and if it 
meets the criteria requesting the password again for confirmation. If both entries match, the 
password is passed to subsequent modules to be set as the new authentication token.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_password\_hashing\_algorithm\_auth\_stig
### Title: Set Password Hashing Algorithm for PAM
### Description:

```
The PAM system service can be configured to only store encrypted representations of passwords.
In "/etc/pam.d/common-password", the password section of the file controls which
PAM modules to execute during a password change.

Set the pam_unix.so module in the password section to include the option
sha512 and no other hashing algorithms as shown below:

         password    [success=1 default=ignore]   pam_unix.so sha512 
         
This will help ensure that new passwords for local users will be stored using the sha512 algorithm.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_password\_hashing\_algorithm\_logindefs
### Title: Set Password Hashing Algorithm in /etc/login.defs
### Description:

```
In /etc/login.defs, add or update the following line to ensure the system will use
 as the hashing algorithm:
ENCRYPT_METHOD 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_set\_password\_hashing\_algorithm\_systemauth
### Title: Set PAM''s Password Hashing Algorithm
### Description:

```
The PAM system service can be configured to only store encrypted representations of passwords.
In "/etc/pam.d/common-password", the password section of the file controls which
PAM modules to execute during a password change.

Set the pam_unix.so module in the password section to include the option
 and no other hashing
algorithms as shown below:

         password    [success=1 default=ignore]   pam_unix.so 
         
This will help ensure that new passwords for local users will be stored using the
 algorithm.
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
The Ubuntu 24.04 operating system must have vlock installed to allow for session locking.


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


Add or update the following line in /etc/pam.d/common-auth,
placing it above any lines containing pam_unix.so:
auth    [success=2 default=ignore] pam_pkcs11.so 


For general information about enabling smart card authentication, consult
the documentation at:


         
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_nologin\_in\_shells
### Title: Ensure nologin Shell is Not Listed in /etc/shells
### Description:

```
The /sbin/nologin shell is used to restrict accounts from having login access
and should not be listed as a valid login shell in /etc/shells.
To verify that nologin is not listed in /etc/shells, run:
$ grep nologin /etc/shells
The command should return no output.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_ensure\_shadow\_group\_empty
### Title: Ensure shadow Group is Empty
### Description:

```
The shadow group allows system programs which require access the ability
to read the /etc/shadow file. No users should be assigned to the shadow group.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_set\_post\_pw\_existing
### Title: Set existing passwords a period of inactivity before they been locked
### Description:

```
Configure user accounts that have been inactive for over a given period of time
to be automatically disabled by running the following command:
$ sudo chage --inactive 30 USER
        
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_unix\_no\_remember
### Title: Avoid using remember in pam\_unix module
### Description:

```
The remember option stores the last n passwords for each user in /etc/security/opasswd,
enforcing password history and preventing users from reusing the same passwords. However, this feature
relies on the MD5 password hash algorithm, which is less secure. Instead, the pam_pwhistory
module should be used. This module also stores the last n passwords in /etc/security/opasswd
and it uses the password hash algorithm configured in the pam_unix module, such as yescrypt or SHA512,
offering enhanced security.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_password\_pam\_unix\_rounds\_password\_auth
### Title: Set number of Password Hashing Rounds - password-auth
### Description:

```
Configure the number or rounds for the password hashing algorithm. This can be
accomplished by using the rounds option for the pam_unix PAM module.

         
In file /etc/pam.d/common-password append rounds=
to the pam_unix.so entry, as shown below:

password [success=1 default=ignore] pam_unix.so 
        
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_empty\_passwords\_unix
### Title: Prevent Login to Accounts With Empty Password
### Description:

```
If an account is configured for password authentication
but does not have an assigned password, it may be possible to log
into the account without authentication. Remove any instances of the
nullok in
/etc/pam.d/common-{password,auth,account,session,session-noninteractive}
to prevent logins with empty passwords.
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
### Title: Ensure the Group Used by pam\_wheel.so Module Exists on System and is Empty
### Description:

```
Ensure that the group  referenced by
var_pam_wheel_group_for_su variable and used as value for the pam_wheel.so
         group option exists and has no members. This empty group used by
pam_wheel.so in /etc/pam.d/su ensures that no user can run commands with
altered privileges through the su command.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ensure\_root\_access\_controlled
### Title: Ensure root account access is controlled
### Description:

```
There are a number of methods to access the root account directly. 
Without a password set any user would be able to gain access and 
thus control over the entire system.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_groups\_no\_zero\_gid\_except\_root
### Title: Verify Only Group Root Has GID 0
### Description:

```
If any group other than root has a GID of 0, this misconfiguration should
be investigated and the groups other than root should be removed or have
their GID changed.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_invalid\_shell\_accounts\_unlocked
### Title: Verify Non-Interactive Accounts Are Locked
### Description:

```
Accounts meant for non-interactive purposes should be locked to prevent
unauthorized access. Accounts with non-standard shells (those not defined in
/etc/shells) should be locked using usermod -L.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_shelllogin\_for\_systemaccounts
### Title: Ensure that System Accounts Do Not Run a Shell Upon Login
### Description:

```
Some accounts are not associated with a human user of the system, and exist to perform some
administrative functions. Should an attacker be able to log into these accounts, they should
not be granted access to a shell.

         
The login shell for each local account is stored in the last field of each line in
/etc/passwd. System accounts are those user accounts with a user ID less than
1000. The user ID is stored in the third field. If any system account
other than root has a login shell, disable it with the command:
$ sudo usermod -s /sbin/nologin 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_prevent\_direct\_root\_logins
### Title: Direct root Logins Are Not Allowed
### Description:

```
Configure the operating system to prevent direct logins to the
root account by performing the following operations:
$ sudo passwd -l root
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_use\_pam\_wheel\_group\_for\_su
### Title: Enforce Usage of pam\_wheel with Group Parameter for su Authentication
### Description:

```
To ensure that only users who are members of the group set in the group option of
pam_wheel.so module can run commands with altered privileges through the su
command, make sure that the following line exists in the file /etc/pam.d/su:
auth required pam_wheel.so use_uid group=
        
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permission\_user\_bash\_history
### Title: Ensure User Bash History File Has Correct Permissions
### Description:

```
Set the mode of the bash history file to 0600 with the
following command:
$ sudo chmod 0600 /home/
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permission\_user\_init\_files
### Title: Ensure All User Initialization Files Have Mode 0740 Or Less Permissive
### Description:

```
Set the mode of the user initialization files to 0740 with the
following command:
$ sudo chmod 0740 /home/
       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_root\_path\_dirs\_no\_write
### Title: Ensure that Root's Path Does Not Include World or Group-Writable Directories
### Description:

```
For each element in root's path, run:
# ls -ld 
and ensure that write permissions are disabled for group and
other.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_dirs\_unowned\_by\_root
### Title: Ensure that All Root's Path Directories Are Owned by Root
### Description:

```
For each element in root's path, run:
# ls -ld 
and ensure that the directory is owned by the root user.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_root\_path\_all\_dirs
### Title: Ensure that All Entries in The Path of Root Are Directories
### Description:

```
For each element in root's path, run:
# ls -ld 
and ensure that the entry is a directory.
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
add or correct the umask setting in /etc/bash.bashrc to read
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_accounts\_umask\_root
### Title: Ensure the Root Bash Umask is Set Correctly
### Description:

```
To ensure the root user's umask of the Bash shell is set properly,
add or correct the umask setting in /root/.bashrc
or /root/.bashrc to read as follows:
umask 0027
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_apparmor-utils\_installed
### Title: Ensure AppArmor Utils is installed
### Description:

```
AppArmor provide Mandatory Access Controls.
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
The rsyslog service provides syslog-style logging by default on Ubuntu 24.04.

The rsyslog service can be enabled with the following command:
$ sudo systemctl enable rsyslog.service
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ensure\_rtc\_utc\_configuration
### Title: Ensure real-time clock is set to UTC
### Description:

```
Ensure that the system real-time clock (RTC) is set to Coordinated Universal Time (UTC).
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_logging\_services\_active
### Title: Ensure One Logging Service Is In Use
### Description:

```
Ensure that a logging system is active and in use.

systemctl is-active rsyslog systemd-journald

The command should return at least one active.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_filecreatemode
### Title: Ensure rsyslog Default File Permissions Configured
### Description:

```
rsyslog will create logfiles that do not already exist on the system.
This settings controls what permissions will be applied to these newly
created files.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_remote\_access\_monitoring
### Title: Ensure remote access methods are monitored in Rsyslog
### Description:

```
Logging of remote access methods must be implemented to help identify cyber
attacks and ensure ongoing compliance with remote access policies are being
audited and upheld. An examples of a remote access method is the use of the
Remote Desktop Protocol (RDP) from an external, non-organization controlled
network. The /etc/rsyslog.d/50-default.conf file should contain a match for the following
selectors: auth.*, authpriv.*, and daemon.*. If
not, use the following as an example configuration:

    auth.*;authpriv.*                              /var/log/secure
    daemon.*                                       /var/log/messages

       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_systemd-journal-remote\_installed
### Title: Install systemd-journal-remote Package
### Description:

```
Journald (via systemd-journal-remote ) supports the ability to send
log events it gathers to a remote log host or to receive messages
from remote hosts, thus enabling centralised log management.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_systemd-journal-upload\_enabled
### Title: Enable systemd-journal-upload Service
### Description:

```
Ubuntu 24.04 must offload rsyslog messages for networked systems in real time and
offload standalone systems at least weekly.

The systemd-journal-upload service can be enabled with the following command:
$ sudo systemctl enable systemd-journal-upload.service
       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_journald\_disable\_forward\_to\_syslog
### Title: Ensure journald ForwardToSyslog is disabled
### Description:

```
Data from journald should be kept in the confines of the service and not forwarded to other services.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_journald\_forward\_to\_syslog
### Title: Ensure journald is configured to send logs to rsyslog
### Description:

```
Data from journald may be stored in volatile memory or persisted locally.
Utilities exist to accept remote export of journald logs.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_journald\_storage
### Title: Ensure journald is configured to write log files to persistent disk
### Description:

```
The journald system may store log files in volatile memory or locally on disk.
If the logs are only stored in volatile memory they will be lost upon reboot.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_systemd\_journal\_upload\_server\_tls
### Title: Configure systemd-journal-upload TLS parameters: ServerKeyFile, ServerCertificateFile and TrustedCertificateFile
### Description:

```
Ubuntu 24.04 must offload rsyslog messages for networked systems in real time and
offload standalone systems at least weekly
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_systemd\_journal\_upload\_url
### Title: Configure systemd-journal-upload URL
### Description:

```
Ubuntu 24.04 must offload rsyslog messages for networked systems in real time and
offload standalone systems at least weekly
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_rsyslog\_nolisten
### Title: Ensure rsyslog Does Not Accept Remote Messages Unless Acting As Log Server
### Description:

```
The rsyslog daemon should not accept remote messages unless the system acts as a log
server. To ensure that it is not listening on the network, ensure any of the following lines
are not found in rsyslog configuration files.

If using legacy syntax:
$ModLoad imtcp
$InputTCPServerRun 

If using RainerScript syntax:
module(load="imtcp")
module(load="imudp")
input(type="imtcp" port="514")
input(type="imudp" port="514")

       
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
        
Or in RainerScript:
*.* action(type="omfwd" ... target="
        
To use TCP for log message delivery:
*.* @@
        
Or in RainerScript:
*.* action(type="omfwd" ... target="
        
To use RELP for log message delivery:
*.* :omrelp:
        
Or in RainerScript:
*.* action(type="omfwd" ... target="
        
There must be a resolvable DNS CNAME or Alias record set to "" for logs to be sent correctly to the centralized logging utility.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_firewall\_single\_service\_active
### Title: Ensure Only One Firewall Service is Active
### Description:

```
The system must have exactly one active firewall service running to avoid conflicts
and ensure consistent packet filtering. Only one of the following services should
be enabled and active at any time:

Having zero active firewalls leaves the system vulnerable, while having multiple
active firewalls can lead to rule conflicts and security gaps.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_net\_ipv4\_conf\_all\_log\_martians
### Title: Enable Kernel Parameter to Log Martian Packets on all IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.log_martians kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.log_martians=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.log_martians = 1
        
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
### Title: Verify nftables Service is Disabled
### Description:

```
nftables is a subsystem of the Linux kernel providing filtering and classification of network
packets/datagrams/frames and is the successor to iptables.
The nftables service can be disabled with the following command:
systemctl disable nftables
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_nftables\_ensure\_default\_deny\_policy
### Title: Ensure nftables Default Deny Firewall Policy
### Description:

```
Base chain policy is the default verdict that will be applied to packets reaching the end of
the chain. There are two policies: accept (Default) and drop. If the policy is set to accept,
the firewall will accept any packet that is not configured to be denied and the packet will
continue traversing the network stack.

Run the following commands and verify that base chains contain a policy of DROP.

$ nft list ruleset | grep 'hook input'
type filter hook input priority 0; policy drop;
$ nft list ruleset | grep 'hook forward'
type filter hook forward priority 0; policy drop;
$ nft list ruleset | grep 'hook output'
type filter hook output priority 0; policy drop;

       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_nftables\_rules\_permanent
### Title: Ensure nftables Rules are Permanent
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
### Title: Set nftables Configuration for Loopback Traffic
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_bluetooth\_disabled
### Title: Disable Bluetooth Service
### Description:

```
The bluetooth service can be disabled with the following command:
$ sudo systemctl mask --now bluetooth.service
         $ sudo service bluetooth stop
        
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
When the so-called 'sticky bit' is set on a directory, only the owner of a given file may
remove that file from the directory. Without the sticky bit, any user with write access to a
directory may remove any file in the directory. Setting the sticky bit prevents users from
removing each other's files. In cases where there is no reason for a directory to be
world-writable, a better solution is to remove that permission rather than to set the sticky
bit. However, if a directory is used by a particular application, consult that application's
documentation instead of blindly changing modes.

To set the sticky bit on a world-writable directory DIR, run the following command:
$ sudo chmod +t 
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_unauthorized\_world\_writable
### Title: Ensure No World-Writable Files Exist
### Description:

```
It is generally a good idea to remove global (other) write access to a file when it is
discovered. However, check with documentation for specific applications before making changes.
Also, monitor for recurring world-writable files, as these may be symptoms of a misconfigured
application or user account. Finally, this applies to real files and not virtual files that
are a part of pseudo file systems such as sysfs or procfs.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_ungroupowned
### Title: Ensure All Files Are Owned by a Group
### Description:

```
If any file is not group-owned by a valid defined group, the cause of the lack of
group-ownership must be investigated. Following this, those files should be deleted or
assigned to an appropriate group. The groups need to be defined in /etc/group
or in /usr/lib/group if nss-altfiles are configured to be used
in /etc/nsswitch.conf.

Locate the mount points related to local devices by the following command:
$ findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,)

For all mount points listed by the previous command, it is necessary to search for files which
do not belong to a valid group using the following command:
$ sudo find 
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_stig
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_no\_files\_unowned\_by\_user
### Title: Ensure All Files Are Owned by a User
### Description:

```
If any files are not owned by a user, then the cause of their lack of ownership should be
investigated. Following this, the files should be deleted or assigned to an appropriate user.

Locate the mount points related to local devices by the following command:
$ findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,)

For all mount points listed by the previous command, it is necessary to search for files which
do not belong to a valid user using the following command:
$ sudo find 
       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_backup\_etc\_group
### Title: Verify Group Who Owns Backup group File
### Description:

```
 To properly set the group owner of /etc/group-, run the command:
$ sudo chgrp root /etc/group-
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_backup\_etc\_gshadow
### Title: Verify Group Who Owns Backup gshadow File
### Description:

```
 To properly set the group owner of /etc/gshadow-, run the command:
$ sudo chgrp shadow /etc/gshadow-
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_backup\_etc\_passwd
### Title: Verify Group Who Owns Backup passwd File
### Description:

```
 To properly set the group owner of /etc/passwd-, run the command:
$ sudo chgrp root /etc/passwd-
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_backup\_etc\_shadow
### Title: Verify User Who Owns Backup shadow File
### Description:

```
 To properly set the group owner of /etc/shadow-, run the command:
$ sudo chgrp shadow /etc/shadow-
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_group
### Title: Verify Group Who Owns group File
### Description:

```
 To properly set the group owner of /etc/group, run the command:
$ sudo chgrp root /etc/group
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_gshadow
### Title: Verify Group Who Owns gshadow File
### Description:

```
 To properly set the group owner of /etc/gshadow, run the command:
$ sudo chgrp shadow /etc/gshadow
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_passwd
### Title: Verify Group Who Owns passwd File
### Description:

```
 To properly set the group owner of /etc/passwd, run the command:
$ sudo chgrp root /etc/passwd
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_security\_opasswd
### Title: Verify Group Who Owns /etc/security/opasswd File
### Description:

```
 To properly set the group owner of /etc/security/opasswd, run the command:
$ sudo chgrp root /etc/security/opasswd
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_security\_opasswd\_old
### Title: Verify Group Who Owns /etc/security/opasswd.old File
### Description:

```
 To properly set the group owner of /etc/security/opasswd.old, run the command:
$ sudo chgrp root /etc/security/opasswd.old
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_shadow
### Title: Verify Group Who Owns shadow File
### Description:

```
 To properly set the group owner of /etc/shadow, run the command:
$ sudo chgrp shadow /etc/shadow
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_etc\_shells
### Title: Verify Group Who Owns /etc/shells File
### Description:

```
To properly set the group owner of /etc/shells, run the command:

  $ sudo chgrp root /etc/shells
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_backup\_etc\_group
### Title: Verify User Who Owns Backup group File
### Description:

```
 To properly set the owner of /etc/group-, run the command:
$ sudo chown root /etc/group- 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_backup\_etc\_gshadow
### Title: Verify User Who Owns Backup gshadow File
### Description:

```
 To properly set the owner of /etc/gshadow-, run the command:
$ sudo chown root /etc/gshadow- 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_backup\_etc\_passwd
### Title: Verify User Who Owns Backup passwd File
### Description:

```
 To properly set the owner of /etc/passwd-, run the command:
$ sudo chown root /etc/passwd- 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_backup\_etc\_shadow
### Title: Verify Group Who Owns Backup shadow File
### Description:

```
 To properly set the owner of /etc/shadow-, run the command:
$ sudo chown root /etc/shadow- 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_group
### Title: Verify User Who Owns group File
### Description:

```
 To properly set the owner of /etc/group, run the command:
$ sudo chown root /etc/group 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_gshadow
### Title: Verify User Who Owns gshadow File
### Description:

```
 To properly set the owner of /etc/gshadow, run the command:
$ sudo chown root /etc/gshadow 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_passwd
### Title: Verify User Who Owns passwd File
### Description:

```
 To properly set the owner of /etc/passwd, run the command:
$ sudo chown root /etc/passwd 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_security\_opasswd
### Title: Verify User Who Owns /etc/security/opasswd File
### Description:

```
 To properly set the owner of /etc/security/opasswd, run the command:
$ sudo chown root /etc/security/opasswd 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_security\_opasswd\_old
### Title: Verify User Who Owns /etc/security/opasswd.old File
### Description:

```
 To properly set the owner of /etc/security/opasswd.old, run the command:
$ sudo chown root /etc/security/opasswd.old 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_shadow
### Title: Verify User Who Owns shadow File
### Description:

```
 To properly set the owner of /etc/shadow, run the command:
$ sudo chown root /etc/shadow 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_etc\_shells
### Title: Verify Who Owns /etc/shells File
### Description:

```
To properly set the owner of /etc/shells, run the command:

  $ sudo chown root /etc/shells 
        
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
To properly set the permissions of /etc/group, run the command:
$ sudo chmod 0644 /etc/group
        
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_security\_opasswd
### Title: Verify Permissions on /etc/security/opasswd File
### Description:

```
To properly set the permissions of /etc/security/opasswd, run the command:
$ sudo chmod 0600 /etc/security/opasswd
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_security\_opasswd\_old
### Title: Verify Permissions on /etc/security/opasswd.old File
### Description:

```
To properly set the permissions of /etc/security/opasswd.old, run the command:
$ sudo chmod 0600 /etc/security/opasswd.old
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_shadow
### Title: Verify Permissions on shadow File
### Description:

```
To properly set the permissions of /etc/shadow, run the command:
$ sudo chmod 0640 /etc/shadow
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_etc\_shells
### Title: Verify Permissions on /etc/shells File
### Description:

```
To properly set the permissions of /etc/shells, run the command:
$ sudo chmod 0644 /etc/shells
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log
### Title: Verify Group Who Owns /var/log Directory
### Description:

```
 To properly set the group owner of /var/log, run the command:
$ sudo chgrp syslog /var/log
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log\_auth
### Title: Verify Group Who Owns /var/log/auth.log File
### Description:

```
 To properly set the group owner of /var/log/auth.log, run the command:
$ sudo chgrp adm /var/log/auth.log or
$ sudo chgrp root /var/log/auth.log
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log\_cloud\_init
### Title: Verify Group Who Owns /var/log/cloud-init.log\* File
### Description:

```
 To properly set the group owner of /var/log/cloud-init.log*, run the command:
$ sudo chgrp adm /var/log/cloud-init.log* or
$ sudo chgrp root /var/log/cloud-init.log*
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log\_journal
### Title: Verify Group Who Owns /var/log/\*.journal(~) File
### Description:

```
 To properly set the group owner of /var/log/*.journal(~), run the command:
$ sudo chgrp systemd-journal /var/log/*.journal(~) or
$ sudo chgrp root /var/log/*.journal(~)
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log\_lastlog
### Title: Verify Group Who Owns /var/log/lastlog File
### Description:

```
 To properly set the group owner of /var/log/lastlog, run the command:
$ sudo chgrp utmp /var/log/lastlog or
$ sudo chgrp root /var/log/lastlog
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log\_localmessages
### Title: Verify Group Who Owns /var/log/localmessages\* File
### Description:

```
 To properly set the group owner of /var/log/localmessages*, run the command:
$ sudo chgrp adm /var/log/localmessages* or
$ sudo chgrp root /var/log/localmessages*
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log\_messages
### Title: Verify Group Who Owns /var/log/messages File
### Description:

```
 To properly set the group owner of /var/log/messages, run the command:
$ sudo chgrp adm /var/log/messages or
$ sudo chgrp root /var/log/messages
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log\_secure
### Title: Verify Group Who Owns /var/log/secure File
### Description:

```
 To properly set the group owner of /var/log/secure, run the command:
$ sudo chgrp adm /var/log/secure or
$ sudo chgrp root /var/log/secure
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log\_syslog
### Title: Verify Group Who Owns /var/log/syslog File
### Description:

```
 To properly set the group owner of /var/log/syslog, run the command:
$ sudo chgrp adm /var/log/syslog or
$ sudo chgrp root /var/log/syslog
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log\_waagent
### Title: Verify Group Who Owns /var/log/waagent.log File
### Description:

```
 To properly set the group owner of /var/log/waagent.log, run the command:
$ sudo chgrp adm /var/log/waagent.log or
$ sudo chgrp root /var/log/waagent.log
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_var\_log\_wbtmp
### Title: Verify Group Who Owns /var/log/(b|w)tmp(.\*|-\*) File
### Description:

```
 To properly set the group owner of /var/log/(b|w)tmp(.*|-*), run the command:
$ sudo chgrp utmp /var/log/(b|w)tmp(.*|-*) or
$ sudo chgrp root /var/log/(b|w)tmp(.*|-*)
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownerships\_var\_log
### Title: Verify ownership of log files
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownerships\_var\_log\_apt
### Title: Verify Groupownership of Files in /var/log/apt
### Description:

```
 To properly set the group owner of /var/log/apt/*, run the command:
$ sudo chgrp adm /var/log/apt/* or
$ sudo chgrp root /var/log/apt/*
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownerships\_var\_log\_gdm
### Title: Verify Groupownership of Files in /var/log/gdm
### Description:

```
 To properly set the group owner of /var/log/gdm/*, run the command:
$ sudo chgrp gdm /var/log/gdm/* or
$ sudo chgrp root /var/log/gdm/*
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownerships\_var\_log\_gdm3
### Title: Verify Groupownership of Files in /var/log/gdm3
### Description:

```
 To properly set the group owner of /var/log/gdm3/*, run the command:
$ sudo chgrp gdm /var/log/gdm3/* or
$ sudo chgrp gdm3 /var/log/gdm3/* or
$ sudo chgrp root /var/log/gdm3/*
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownerships\_var\_log\_landscape
### Title: Verify Groupownership of Files in /var/log/landscape
### Description:

```
 To properly set the group owner of /var/log/landscape/*, run the command:
$ sudo chgrp root /var/log/landscape/* or
$ sudo chgrp landscape /var/log/landscape/*
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownerships\_var\_log\_sssd
### Title: Verify Grouponwership of Files in /var/log/sssd
### Description:

```
 To properly set the group owner of /var/log/sssd/*, run the command:
$ sudo chgrp sssd /var/log/sssd/* or
$ sudo chgrp root /var/log/sssd/*
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log
### Title: Verify User Who Owns /var/log Directory
### Description:

```
 To properly set the owner of /var/log, run the command:
$ sudo chown root /var/log 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log\_auth
### Title: Verify User Who Owns /var/log/auth.log File
### Description:

```
 To properly set the owner of /var/log/auth.log, run the command:
$ sudo chown syslog /var/log/auth.log  or
$ sudo chown root /var/log/auth.log 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log\_cloud\_init
### Title: Verify User Who Owns /var/log/cloud-init.log File
### Description:

```
 To properly set the owner of /var/log/cloud-init.log, run the command:
$ sudo chown syslog /var/log/cloud-init.log  or
$ sudo chown root /var/log/cloud-init.log 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log\_journal
### Title: Verify User Who Owns /var/log/\*.journal(~) Files
### Description:

```
 To properly set the owner of /var/log/*.journal(~), run the command:
$ sudo chown root /var/log/*.journal(~) 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log\_lastlog
### Title: Verify User Who Owns /var/log/lastlog File
### Description:

```
 To properly set the owner of /var/log/lastlog, run the command:
$ sudo chown root /var/log/lastlog 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log\_localmessages
### Title: Verify User Who Owns /var/log/localmessages File
### Description:

```
 To properly set the owner of /var/log/localmessages, run the command:
$ sudo chown syslog /var/log/localmessages  or
$ sudo chown root /var/log/localmessages 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log\_messages
### Title: Verify User Who Owns /var/log/messages File
### Description:

```
 To properly set the owner of /var/log/messages, run the command:
$ sudo chown syslog /var/log/messages  or
$ sudo chown root /var/log/messages 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log\_secure
### Title: Verify User Who Owns /var/log/secure File
### Description:

```
 To properly set the owner of /var/log/secure, run the command:
$ sudo chown syslog /var/log/secure  or
$ sudo chown root /var/log/secure 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log\_syslog
### Title: Verify User Who Owns /var/log/syslog File
### Description:

```
 To properly set the owner of /var/log/syslog, run the command:
$ sudo chown syslog /var/log/syslog  or
$ sudo chown root /var/log/syslog 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log\_waagent
### Title: Verify User Who Owns /var/log/waagent.log File
### Description:

```
 To properly set the owner of /var/log/waagent.log, run the command:
$ sudo chown syslog /var/log/waagent.log  or
$ sudo chown root /var/log/waagent.log 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_var\_log\_wbtmp
### Title: Verify User Who Owns /var/log/(b|w)tmp(.\*|-\*) File
### Description:

```
 To properly set the owner of /var/log/(b|w)tmp(.*|-*), run the command:
$ sudo chown root /var/log/(b|w)tmp(.*|-*) 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownerships\_var\_log
### Title: Verify ownership of log files
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownerships\_var\_log\_apt
### Title: Verify Ownership of Files in /var/log/apt
### Description:

```
 To properly set the owner of /var/log/apt/*, run the command:
$ sudo chown root /var/log/apt/* 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownerships\_var\_log\_gdm
### Title: Verify Ownership of Files in /var/log/gdm
### Description:

```
 To properly set the owner of /var/log/gdm/*, run the command:
$ sudo chown root /var/log/gdm/* 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownerships\_var\_log\_gdm3
### Title: Verify Ownership of Files in /var/log/gdm3
### Description:

```
 To properly set the owner of /var/log/gdm3/*, run the command:
$ sudo chown root /var/log/gdm3/* 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownerships\_var\_log\_landscape
### Title: Verify Ownership of Files in /var/log/landscape
### Description:

```
 To properly set the owner of /var/log/landscape/*, run the command:
$ sudo chown root /var/log/landscape/*  or
$ sudo chown landscape /var/log/landscape/* 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownerships\_var\_log\_sssd
### Title: Verify Ownership of Files in /var/log/sssd
### Description:

```
 To properly set the owner of /var/log/sssd/*, run the command:
$ sudo chown sssd /var/log/sssd/*  or
$ sudo chown root /var/log/sssd/* 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log
### Title: Verify Permissions on /var/log Directory
### Description:

```
To properly set the permissions of /var/log, run the command:
$ sudo chmod 0755 /var/log
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_apt
### Title: Verify Permissions on files in the /var/log/apt/.\* directory
### Description:

```
To properly set the permissions of /var/log/apt/.*, run the command:
$ sudo chmod 0644 /var/log/apt/.*
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_auth
### Title: Verify Permissions on /var/log/auth.log File
### Description:

```
To properly set the permissions of /var/log/auth.log, run the command:
$ sudo chmod 0640 /var/log/auth.log
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_cloud-init
### Title: Verify Permissions on /var/log/cloud-init.log(.\*) Files
### Description:

```
To properly set the permissions of /var/log/cloud-init.log, run the command:
$ sudo chmod 0644 /var/log/cloud-init.log
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_gdm
### Title: Verify Permissions of Files in /var/log/gdm
### Description:

```
To properly set the permissions of /var/log/gdm/*, run the command:
$ sudo chmod 0660 /var/log/gdm/*
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_gdm3
### Title: Verify Permissions of Files in /var/log/gdm3
### Description:

```
To properly set the permissions of /var/log/gdm3/*, run the command:
$ sudo chmod 0660 /var/log/gdm3/*
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_lastlog
### Title: Verify Permissions on /var/log/lastlog(.\*) Files
### Description:

```
To properly set the permissions of /var/log/lastlog, run the command:
$ sudo chmod 0664 /var/log/lastlog
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_localmessages
### Title: Verify Permissions on /var/log/localmessages(.\*) Files
### Description:

```
To properly set the permissions of /var/log/localmessages, run the command:
$ sudo chmod 0644 /var/log/localmessages
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_messages
### Title: Verify Permissions on /var/log/messages File
### Description:

```
To properly set the permissions of /var/log/messages, run the command:
$ sudo chmod 0640 /var/log/messages
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_secure
### Title: Verify Permissions on /var/log/secure File
### Description:

```
To properly set the permissions of /var/log/secure, run the command:
$ sudo chmod 0640 /var/log/secure
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_sssd
### Title: Verify Permissions of Files in /var/log/sssd
### Description:

```
To properly set the permissions of /var/log/sssd/*, run the command:
$ sudo chmod 0660 /var/log/sssd/*
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_syslog
### Title: Verify Permissions on /var/log/syslog File
### Description:

```
To properly set the permissions of /var/log/syslog, run the command:
$ sudo chmod 0640 /var/log/syslog
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_waagent
### Title: Verify Permissions on /var/log/waagent.log(.\*) Files
### Description:

```
To properly set the permissions of /var/log/waagent.log, run the command:
$ sudo chmod 0644 /var/log/waagent.log
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_var\_log\_wbtmp
### Title: Verify Permissions on /var/log/wtmp(.\*) Files
### Description:

```
To properly set the permissions of /var/log/(b|w)tmp(.*|-*), run the command:
$ sudo chmod 0664 /var/log/(b|w)tmp(.*|-*)
        
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
"/lib", "/lib64", "/usr/lib/" and "/usr/lib64" are group-owned by root or a required system account.
### Description:

```
System-wide library files are stored in the following directories
by default:
/lib
/lib64
/usr/lib
/usr/lib64

All system-wide shared library files should be protected from unauthorised
access. If any of these files is not group-owned by root or a required system account,
correct its group-owner with the following command:
$ sudo chgrp root 
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_autofs\_removed
### Title: Remove autofs Package
### Description:

```
autofs allows automatic mounting of devices, typically including CD/DVDs and USB
drives.
 The autofs package can be removed with the following command:
 
 $ apt-get remove autofs
       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_freevxfs\_disabled
### Title: Disable Mounting of freevxfs
### Description:

```
To configure the system to prevent the freevxfs
kernel module from being loaded, add the following line to the file /etc/modprobe.d/freevxfs.conf:
install freevxfs /bin/false

This effectively prevents usage of this uncommon filesystem.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_jffs2\_disabled
### Title: Disable Mounting of jffs2
### Description:

```
To configure the system to prevent the jffs2
kernel module from being loaded, add the following line to the file /etc/modprobe.d/jffs2.conf:
install jffs2 /bin/false

This effectively prevents usage of this uncommon filesystem.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_kernel\_module\_overlayfs\_disabled
### Title: Ensure overlayfs kernel module is not available
### Description:

```
To configure the system to prevent the overlayfs
kernel module from being loaded, add the following line to the file /etc/modprobe.d/overlayfs.conf:
install overlayfs /bin/false

overlayfs is a Linux filesystem that layers multiple filesystems to create a single
unified view which allows a user to "merge" several mount points into a unified
filesystem.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_kernel\_dmesg\_restrict
### Title: Restrict Access to Kernel Message Buffer
### Description:

```
To set the runtime status of the kernel.dmesg_restrict kernel parameter, run the following command: $ sudo sysctl -w kernel.dmesg_restrict=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: kernel.dmesg_restrict = 1
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sysctl\_kernel\_yama\_ptrace\_scope
### Title: Restrict usage of ptrace to descendant processes
### Description:

```
To set the runtime status of the kernel.yama.ptrace_scope kernel parameter, run the following command: $ sudo sysctl -w kernel.yama.ptrace_scope=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: kernel.yama.ptrace_scope = 1
       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_at\_allow\_exists
### Title: Ensure that /etc/at.allow exists
### Description:

```
The file /etc/at.allow should exist and should be used instead
of /etc/at.deny.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_cron\_allow\_exists
### Title: Ensure that /etc/cron.allow exists
### Description:

```
The file /etc/cron.allow should exist and should be used instead
of /etc/cron.deny.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_at\_deny
### Title: Verify Group Who Owns /etc/at.deny file
### Description:

```
If /etc/at.deny exists, it must be group-owned by root.

To properly set the group owner of /etc/at.deny, run the command:

  $ sudo chgrp root /etc/at.deny
       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_owner\_at\_deny
### Title: Verify User Who Owns /etc/at.deny file
### Description:

```
If /etc/at.deny exists, it must be owned by root.

To properly set the owner of /etc/at.deny, run the command:

  $ sudo chown root /etc/at.deny 
       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_at\_deny
### Title: Verify Permissions on /etc/at.deny file
### Description:

```
If /etc/at.deny exists, it must have permissions 0640
or more restrictive.


To properly set the permissions of /etc/at.deny, run the command:
$ sudo chmod 0640 /etc/at.deny
       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_nis\_removed
### Title: Uninstall the nis package
### Description:

```
The support for Yellowpages should not be installed unless it is required.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_telnetd\_removed
### Title: Uninstall the telnet server
### Description:

```
The telnet daemon should be uninstalled.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_dhcpd6\_disabled
### Title: Disable DHCPD6 Service
### Description:

```
The dhcp6 service should be disabled on
any system that does not need to act as a DHCP server.


The isc-dhcp-server6 service can be disabled with the following command:
$ sudo systemctl mask --now isc-dhcp-server6.service
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_dhcpd\_disabled
### Title: Disable DHCP Service
### Description:

```
The dhcpd service should be disabled on
any system that does not need to act as a DHCP server.


The isc-dhcp-server service can be disabled with the following command:
$ sudo systemctl mask --now isc-dhcp-server.service
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_dnsmasq\_removed
### Title: Uninstall dnsmasq Package
### Description:

```
dnsmasq is a lightweight tool that provides DNS caching, DNS forwarding and
DHCP (Dynamic Host Configuration Protocol) services.

The dnsmasq package can be removed with the following command:

$ apt-get remove dnsmasq
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_dnsmasq\_disabled
### Title: Disable dnsmasq Service
### Description:

```
The dnsmasq service can be disabled with the following command:
$ sudo systemctl mask --now dnsmasq.service
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_bind\_removed
### Title: Uninstall bind Package
### Description:

```
The named service is provided by the bind package.
The bind package can be removed with the following command:

$ apt-get remove bind
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_named\_disabled
### Title: Disable named Service
### Description:

```
The named service can be disabled with the following command:
$ sudo systemctl mask --now named.service
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_ftp\_removed
### Title: Remove ftp Package
### Description:

```
FTP (File Transfer Protocol) is a traditional and widely used standard tool for
transferring files between a server and clients over a network, especially where no
authentication is necessary (permits anonymous users to connect to a server).

The ftp package can be removed with the following command:

$ apt-get remove ftp
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_tnftp\_removed
### Title: Remove tnftp Package
### Description:

```
tnftp an enhanced FTP client, is the user interface to the Internet standard File
Transfer Protocol. The program allows a user to transfer files to and from a remote
network site.
The ftp package can be removed with the following command:

$ apt-get remove ftp
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_vsftpd\_removed
### Title: Uninstall vsftpd Package
### Description:

```
The vsftpd package can be removed with the following command:  $ apt-get remove vsftpd
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_vsftpd\_disabled
### Title: Disable vsftpd Service
### Description:

```
The vsftpd service can be disabled with the following command:
$ sudo systemctl mask --now vsftpd.service
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_httpd\_removed
### Title: Uninstall apache2 Package
### Description:

```
The apache2 package can be removed with the following command:

$ apt-get remove apache2
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_httpd\_disabled
### Title: Disable apache2 Service
### Description:

```
The apache2 service can be disabled with the following command:
$ sudo systemctl mask --now apache2.service
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_nginx\_removed
### Title: Uninstall nginx Package
### Description:

```
The nginx package can be removed with the following command:

$ apt-get remove nginx
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_nginx\_disabled
### Title: Disable nginx Service
### Description:

```
The nginx service can be disabled with the following command:
$ sudo systemctl mask --now nginx.service
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_dovecot\_removed
### Title: Uninstall dovecot Package
### Description:

```
The dovecot-core package can be removed with the following command:

$ apt-get remove dovecot-core
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_dovecot\_disabled
### Title: Disable Dovecot Service
### Description:

```
The dovecot service can be disabled with the following command:
$ sudo systemctl mask --now dovecot.service
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_openldap-clients\_removed
### Title: Ensure LDAP client is not installed
### Description:

```
The Lightweight Directory Access Protocol (LDAP) is a service that provides
a method for looking up information from a central database.
The ldap-utils package can be removed with the following command:

$ apt-get remove ldap-utils
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_openldap-servers\_removed
### Title: Uninstall openldap-servers Package
### Description:

```
The slapd package is not installed by default on a Ubuntu 24.04
system. It is needed only by the OpenLDAP server, not by the
clients which use LDAP for authentication. If the system is not
intended for use as an LDAP Server it should be removed.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_slapd\_disabled
### Title: Disable LDAP Server (slapd)
### Description:

```
The Lightweight Directory Access Protocol (LDAP) is a service that
provides a method for looking up information from a central database.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_rpcbind\_disabled
### Title: Disable rpcbind Service
### Description:

```
The rpcbind utility maps RPC services to the ports on which they listen.
RPC processes notify rpcbind when they start, registering the ports they
are listening on and the RPC program numbers they expect to serve. The
rpcbind service redirects the client to the proper port number so it can
communicate with the requested service. If the system does not require RPC
(such as for NFS servers) then this service should be disabled.

The rpcbind service can be disabled with the following command:
$ sudo systemctl mask --now rpcbind.service
        
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_nfs\_disabled
### Title: Disable Network File System (nfs)
### Description:

```
The Network File System (NFS) service allows remote hosts to mount
and interact with shared filesystems on the local system. If the local system
is not designated as a NFS server then this service should be disabled.

The nfs-server service can be disabled with the following command:
$ sudo systemctl mask --now nfs-server.service
        
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

    https://chrony-project.org/.
Chrony can be configured to be a client and/or a server.
To enable Chronyd service, you can run:
# systemctl enable chronyd.service
This recommendation only applies if chrony is in use on the system.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_timesyncd\_enabled
### Title: Enable systemd\_timesyncd Service
### Description:

```
The systemd_timesyncd service can be enabled with the following command:
$ sudo systemctl enable systemd_timesyncd.service
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_chronyd\_disabled
### Title: The Chronyd service is disabled
### Description:

```
The chrony service can be disabled with the following command:
$ sudo systemctl mask --now chrony.service
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_timesyncd\_disabled
### Title: Disable systemd\_timesyncd Service
### Description:

```
The systemd_timesyncd service can be disabled with the following command:
$ sudo systemctl mask --now systemd_timesyncd.service
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_chronyd\_specify\_remote\_server
### Title: A remote time server for Chrony is configured
### Description:

```
Chrony is a daemon which implements the Network Time Protocol (NTP). It is designed
to synchronize system clocks across a variety of systems and use a source that is highly
accurate. More information on chrony can be found at

    https://chrony-project.org/.
Chrony can be configured to be a client and/or a server.
Add or edit server or pool lines to /etc/chrony/chrony.conf as appropriate:
server <remote-server>
Multiple servers may be configured.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_chronyd\_configure\_pool\_and\_server
### Title: Chrony Configure Pool and Server
### Description:

```
Chrony is a daemon which implements the Network Time Protocol (NTP). It is designed to
synchronize system clocks across a variety of systems and use a source that is highly
accurate. More information on chrony can be found at

    https://chrony-project.org/.
Chrony can be configured to be a client and/or a server.
Add or edit server or pool lines to /etc/chrony/chrony.conf as appropriate:
server <remote-server>
Multiple servers may be configured.
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

    https://chrony-project.org/.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_chronyd\_sync\_clock
### Title: Synchronize internal information system clocks
### Description:

```
Synchronizing internal information system clocks provides uniformity
of time stamps for information systems with multiple system clocks and
systems connected over a network.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ntp\_single\_service\_active
### Title: Ensure a Single Time Synchronization Service is in Use
### Description:

```
The system must have exactly one active time synchronization service to avoid conflicts
and ensure consistent time synchronization. Only one of the following services should be
enabled and active at any time:

Having zero active time synchronization services leaves the system without accurate
time synchronization, while having multiple active services can lead to unexpected and
unreliable results.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_timesyncd\_configured
### Title: Configure Systemd Timesyncd Servers
### Description:

```
systemd-timesyncd is a daemon that has been added for synchronizing the system clock
across the network. The systemd-timesyncd daemon implements:
  - Implements an SNTP client
  - Runs with minimal privileges
  - Saves the current clock to disk every time a new NTP sync has been acquired
  - Is hooked up with networkd to only operate when network connectivity is available
Add or edit server or pool lines to /etc/systemd/timesyncd.conf as appropriate:
server <remote-server>
Multiple servers may be configured.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_rsync\_removed
### Title: Uninstall rsync Package
### Description:

```
The rsyncd service can be used to synchronize files between systems over network links.
The rsync package can be removed with the following command:

$ apt-get remove rsync
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_rsyncd\_disabled
### Title: Ensure rsyncd service is disabled
### Description:

```
The rsyncd service can be disabled with the following command:
$ sudo systemctl mask --now rsyncd.service
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_xinetd\_removed
### Title: Uninstall xinetd Package
### Description:

```
The xinetd package can be removed with the following command:

$ apt-get remove xinetd
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_xinetd\_disabled
### Title: Disable xinetd Service
### Description:

```
The xinetd service can be disabled with the following command:
$ sudo systemctl mask --now xinetd.service
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_ypserv\_removed
### Title: Uninstall ypserv Package
### Description:

```
The ypserv package can be removed with the following command:

$ apt-get remove ypserv
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_ypserv\_disabled
### Title: Disable ypserv Service
### Description:

```
The ypserv service, which allows the system to act as a client in
a NIS or NIS+ domain, should be disabled.

The ypserv service can be disabled with the following command:
$ sudo systemctl mask --now ypserv.service
       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_inetutils-telnet\_removed
### Title: Remove telnet Clients
### Description:

```
The telnet client allows users to start connections to other systems via
the telnet protocol.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_telnet\_removed
### Title: Remove telnet Clients
### Description:

```
The telnet client allows users to start connections to other systems via
the telnet protocol.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_tftp-server\_removed
### Title: Uninstall tftpd-hpa Package
### Description:

```
The tftpd-hpa package can be removed with the following command:  $ apt-get remove tftpd-hpa
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_tftp\_disabled
### Title: Disable tftpd-hpa Service
### Description:

```
The tftpd-hpa service should be disabled.

The tftpd-hpa service can be disabled with the following command:
$ sudo systemctl mask --now tftpd-hpa.service
       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_squid\_disabled
### Title: Disable Squid
### Description:

```
The squid service can be disabled with the following command:
$ sudo systemctl mask --now squid.service
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_samba\_removed
### Title: Uninstall Samba Package
### Description:

```
The samba package can be removed with the following command:  $ apt-get remove samba
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_smb\_disabled
### Title: Disable Samba
### Description:

```
The smb service can be disabled with the following command:
$ sudo systemctl mask --now smb.service
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_net-snmp\_removed
### Title: Uninstall net-snmp Package
### Description:

```
The snmp package provides the snmpd service.
The snmp package can be removed with the following command:

$ apt-get remove snmp
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_snmpd\_disabled
### Title: Disable snmpd Service
### Description:

```
The snmpd service can be disabled with the following command:
$ sudo systemctl mask --now snmpd.service
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_openssh-server\_installed
### Title: Install the OpenSSH Server Package
### Description:

```
The openssh-server package should be installed.
The openssh-server package can be installed with the following command:

$ apt-get install openssh-server
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_sshd\_enabled
### Title: Enable the OpenSSH Service
### Description:

```
The SSH server service, sshd, is commonly needed.

The sshd service can be enabled with the following command:
$ sudo systemctl enable sshd.service
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupowner\_sshd\_config
### Title: Verify Group Who Owns SSH Server config file
### Description:

```
To properly set the group owner of /etc/ssh/sshd_config, run the command:

  $ sudo chgrp root /etc/ssh/sshd_config
      
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_ssh\_client\_use\_approved\_ciphers\_ordered\_stig
### Title: Use Only FIPS 140-3 Validated Ciphers in SSH Client Configuration
### Description:

```
Limit the ciphers to those algorithms which are FIPS-approved.
The following line in /etc/ssh/ssh_config
demonstrates use of FIPS-approved ciphers:
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr
If this line does not contain these ciphers in exact order,
is commented out, or is missing, this is a finding.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_ssh\_use\_approved\_macs\_ordered\_stig
### Title: Use Only FIPS 140-3 Validated MACs
### Description:

```
Limit the MACs to those hash algorithms which are FIPS-approved.
The following line in /etc/ssh/ssh_config
demonstrates use of FIPS-approved MACs:

MACs 
If this line does not contain these MACs in exact order,
is commented out, or is missing, this is a finding.
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_disable\_forwarding
### Title: Disable SSH Forwarding
### Description:

```
The DisableForwarding parameter disables all forwarding features, 
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
The MaxStartups parameter specifies the maximum number of concurrent unauthenticated
connections to the SSH daemon. Additional connections will be dropped until authentication
succeeds or the LoginGraceTime expires for a connection. To configure MaxStartups, you should
add or edit the following line in the /etc/ssh/sshd_config file:
MaxStartups 
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sshd\_use\_approved\_ciphers\_ordered\_stig
### Title: Use Only FIPS 140-2 Validated Ciphers
### Description:

```
Limit the ciphers to those algorithms which are FIPS-approved.
The following line in /etc/ssh/sshd_config
demonstrates use of FIPS-approved ciphers:
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
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
MACs hmac-sha2-512,hmac-sha2-256
If this line does not contain these MACs in exact order,
is commented out, or is missing, this is a finding.
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
MACs 
       
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_package\_sssd\_installed
### Title: Install the SSSD Package
### Description:

```
The sssd package should be installed.
The sssd package can be installed with the following command:

$ apt-get install sssd
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_service\_sssd\_enabled
### Title: Enable the SSSD Service
### Description:

```
The SSSD service should be enabled.

The sssd service can be enabled with the following command:
$ sudo systemctl enable sssd.service
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sssd\_certification\_path\_trust\_anchor
### Title: Certificate trust path in SSSD
### Description:

```
Enable certification trust path for SSSD to an accepted trust anchor.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sssd\_enable\_pam\_services
### Title: Configure PAM in SSSD Services
### Description:

```
SSSD should be configured to run SSSD pam services.
To configure SSSD to known SSH hosts, add pam
to services under the [sssd] section in
/etc/sssd/sssd.conf. For example:
[sssd]
services = sudo, autofs, pam

      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sssd\_enable\_smartcards
### Title: Enable Smartcards in SSSD
### Description:

```
SSSD should be configured to authenticate access to the system using smart cards.
To enable smart cards in SSSD, set pam_cert_auth to True under the
[pam] section in /etc/sssd/sssd.conf. For example:
[pam]
pam_cert_auth = True

      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_sssd\_enable\_user\_cert
### Title: Enable Certificates Mapping in SSSD
### Description:

```
SSSD needs to be set up to link the authenticated identity to the user or group account
for PKI-based authentication. To implement this, confirm that the /etc/sssd/sssd.conf
file contains the following line

ldap_user_certificate=userCertificate;binary

      
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_mac\_modification\_etc\_apparmor
### Title: Record Events that Modify the System's Mandatory Access Controls (/etc/apparmor)
### Description:

```



If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/apparmor/ -p wa -k MAC-policy

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/apparmor/ -p wa -k MAC-policy
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_mac\_modification\_etc\_apparmor\_d
### Title: Record Events that Modify the System's Mandatory Access Controls (/etc/apparmor.d)
### Description:

```



If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/apparmor.d/ -p wa -k MAC-policy

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/apparmor.d/ -p wa -k MAC-policy
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_media\_export
### Title: Ensure auditd Collects Information on Exporting to Media (successful)
### Description:

```
At a minimum, the audit system should collect media exportation
events for all users and root. If the auditd daemon is configured to
use the augenrules program to read audit rules during daemon startup
(the default), add the following line to a file with suffix .rules in
the directory /etc/audit/rules.d, setting ARCH to either b32 for
32-bit system, or having two lines for both b32 and b64 in case your
system is 64-bit:
-a always,exit -F arch=ARCH -S mount -F auid>=1000 -F auid!=unset -F key=export
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file, setting ARCH to either b32 for
32-bit system, or having two lines for both b32 and b64 in case your
system is 64-bit:
-a always,exit -F arch=ARCH -S mount -F auid>=1000 -F auid!=unset -F key=export
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_networkconfig\_modification
### Title: Record Events that Modify the System's Network Environment
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following lines to a file with suffix .rules in the
directory /etc/audit/rules.d, setting ARCH to either b32 for
32-bit system, or having two lines for both b32 and b64 in case your system
is 64-bit:
-a always,exit -F arch=ARCH -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification

-w /etc/netplan/ -p wa -k audit_rules_networkconfig_modification

-w /etc/networks -p wa -k audit_rules_networkconfig_modification
-w /etc/network/ -p wa -k audit_rules_networkconfig_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file, setting ARCH to either b32 for
32-bit system, or having two lines for both b32 and b64 in case your system
is 64-bit:
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
users and root.




If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /var/log/btmp -p wa -k session

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /var/log/btmp -p wa -k session
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_session\_events\_utmp
### Title: Record Attempts to Alter Process and Session Initiation Information utmp
### Description:

```
The audit system already collects process information for all
users and root.




If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /var/run/utmp -p wa -k session

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /var/run/utmp -p wa -k session
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_session\_events\_wtmp
### Title: Record Attempts to Alter Process and Session Initiation Information wtmp
### Description:

```
The audit system already collects process information for all
users and root.




If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /var/log/wtmp -p wa -k session

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /var/log/wtmp -p wa -k session
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_sudoers
### Title: Ensure auditd Collects System Administrator Actions - /etc/sudoers
### Description:

```
At a minimum, the audit system should collect administrator actions
for all users and root.




If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/sudoers -p wa -k actions

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/sudoers -p wa -k actions
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_sudoers\_d
### Title: Ensure auditd Collects System Administrator Actions - /etc/sudoers.d/
### Description:

```
At a minimum, the audit system should collect administrator actions
for all users and root.




If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/sudoers.d/ -p wa -k actions

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/sudoers.d/ -p wa -k actions
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_suid\_auid\_privilege\_function
### Title: Record Events When Executables Are Run As Another User
### Description:

```
Verify the system generates an audit record when actions are run as another user.
sudo provides users with temporary elevated privileges to perform operations, either as the superuser or another user.

If audit is using the "auditctl" tool to load the rules, run the following command:

$ sudo grep execve /etc/audit/audit.rules

If audit is using the "augenrules" tool to load the rules, run the following command:

$ sudo grep -r execve /etc/audit/rules.d
       -a always,exit -F arch=b32 -S execve -C euid!=uid -F auid!=unset -k user_emulation
       -a always,exit -F arch=b64  S execve -C euid!=uid -F auid!=unset -k user_emulation

If both the "b32" and "b64" audit rules for "SUID" files are not defined, this is a finding.
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



If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/sudoers -p wa -k actions

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/sudoers -p wa -k actions






If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/sudoers.d/ -p wa -k actions

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/sudoers.d/ -p wa -k actions
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_group
### Title: Record Events that Modify User/Group Information - /etc/group
### Description:

```



If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/group -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/group -p wa -k audit_rules_usergroup_modification
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_gshadow
### Title: Record Events that Modify User/Group Information - /etc/gshadow
### Description:

```



If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/gshadow -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_nsswitch\_conf
### Title: Record Events that Modify User/Group Information - /etc/nsswitch.conf
### Description:

```



If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/nsswitch.conf -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/nsswitch.conf -p wa -k audit_rules_usergroup_modification
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_opasswd
### Title: Record Events that Modify User/Group Information - /etc/security/opasswd
### Description:

```



If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_pam\_conf
### Title: Record Events that Modify User/Group Information - /etc/pam.conf
### Description:

```



If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/pam.conf -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/pam.conf -p wa -k audit_rules_usergroup_modification
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_pamd
### Title: Record Events that Modify User/Group Information - /etc/pam.d/
### Description:

```



If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/pam.d/ -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/pam.d/ -p wa -k audit_rules_usergroup_modification
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_passwd
### Title: Record Events that Modify User/Group Information - /etc/passwd
### Description:

```



If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/passwd -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/passwd -p wa -k audit_rules_usergroup_modification
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_usergroup\_modification\_shadow
### Title: Record Events that Modify User/Group Information - /etc/shadow
### Description:

```



If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/shadow -p wa -k audit_rules_usergroup_modification

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

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





If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /var/log/journal -p wa -k systemd_journal

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /var/log/journal -p wa -k systemd_journal
      
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_sudo\_log\_events
### Title: Record Attempts to perform maintenance activities
### Description:

```
The Ubuntu 24.04 operating system must generate audit records for
privileged activities, nonlocal maintenance, diagnostic sessions and
other system-level access.

Verify the operating system audits activities performed during nonlocal
maintenance and diagnostic sessions. Run the following command:
$ sudo auditctl -l | grep sudo.log
-w /var/log/sudo.log -p wa -k maintenance





If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /var/log/sudo.log -p wa -k maintenance

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /var/log/sudo.log -p wa -k maintenance
      
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_execution\_chacl
### Title: Record Any Attempts to Run chacl
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_execution\_setfacl
### Title: Record Any Attempts to Run setfacl
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_execution\_chcon
### Title: Record Any Attempts to Run chcon
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
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
directory /etc/audit/rules.d, setting ARCH to either b32 for 32-bit
system, or having two lines for both b32 and b64 in case your system is 64-bit:
-a always,exit -F arch=ARCH -S rename -F auid>=1000 -F auid!=unset -F key=delete
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file, setting ARCH to either b32 for 32-bit
system, or having two lines for both b32 and b64 in case your system is 64-bit:
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
directory /etc/audit/rules.d, setting ARCH to either b32 for 32-bit
system, or having two lines for both b32 and b64 in case your system is 64-bit:
-a always,exit -F arch=ARCH -S renameat -F auid>=1000 -F auid!=unset -F key=delete
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file, setting ARCH to either b32 for 32-bit
system, or having two lines for both b32 and b64 in case your system is 64-bit:
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
directory /etc/audit/rules.d, setting ARCH to either b32 for 32-bit
system, or having two lines for both b32 and b64 in case your system is 64-bit:
-a always,exit -F arch=ARCH -S rmdir -F auid>=1000 -F auid!=unset -F key=delete
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file, setting ARCH to either b32 for 32-bit
system, or having two lines for both b32 and b64 in case your system is 64-bit:
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
directory /etc/audit/rules.d, setting ARCH to either b32 for 32-bit
system, or having two lines for both b32 and b64 in case your system is 64-bit:
-a always,exit -F arch=ARCH -S unlink -F auid>=1000 -F auid!=unset -F key=delete
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file, setting ARCH to either b32 for 32-bit
system, or having two lines for both b32 and b64 in case your system is 64-bit:
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
directory /etc/audit/rules.d, setting ARCH to either b32 for 32-bit
system, or having two lines for both b32 and b64 in case your system is 64-bit:
-a always,exit -F arch=ARCH -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file, setting ARCH to either b32 for 32-bit
system, or having two lines for both b32 and b64 in case your system is 64-bit:
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_kernel\_module\_loading\_create
### Title: Ensure auditd Collects Information on Kernel Module Unloading - create\_module
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_kernel\_module\_loading\_query
### Title: Ensure auditd Collects Information on Kernel Module Loading and Unloading - query\_module
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_login\_events\_faillock
### Title: Record Attempts to Alter Logon and Logout Events - faillock
### Description:

```
The audit system already collects login information for all users
and root.




If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w 

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w 
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_login\_events\_faillog
### Title: Record Attempts to Alter Logon and Logout Events - faillog
### Description:

```
The audit system already collects login information for all users
and root.




If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /var/log/faillog -p wa -k logins

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /var/log/faillog -p wa -k logins
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_login\_events\_lastlog
### Title: Record Attempts to Alter Logon and Logout Events - lastlog
### Description:

```
The audit system already collects login information for all users
and root.




If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /var/log/lastlog -p wa -k logins

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /var/log/lastlog -p wa -k logins
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands
### Title: Ensure auditd Collects Information on the Use of Privileged Commands
### Description:

```
The audit system should collect information about usage of privileged commands for all users.
These are commands with suid or sgid bits on and they are specially risky in local block
device partitions not mounted with noexec and nosuid options. Therefore, these partitions
should be first identified by the following command:
findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid"

For all partitions listed by the previous command, it is necessary to search for
setuid / setgid programs using the following command:
$ sudo find 

For each setuid / setgid program identified by the previous command, an audit rule must be
present in the appropriate place using the following line structure, setting ARCH to either b32 for 32-bit
system, or having two lines for both b32 and b64 in case your system is 64-bit:
-a always,exit -F arch=ARCH -F path=

If the auditd daemon is configured to use the augenrules program to read
audit rules during daemon startup, add the line to a file with suffix .rules in the
/etc/audit/rules.d directory, replacing the PROG_PATH part with the full path
of that setuid / setgid identified program.

If the auditd daemon is configured to use the auditctl utility instead, add
the line to the /etc/audit/audit.rules file, also replacing the PROG_PATH part
with the full path of that setuid / setgid identified program.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_apparmor\_parser
### Title: Record Any Attempts to Run apparmor\_parser
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_chage
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - chage
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_chfn
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - chfn
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_chsh
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - chsh
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_crontab
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - crontab
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
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


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_kmod
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - kmod
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
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


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_newgrp
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - newgrp
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_pam\_timestamp\_check
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - pam\_timestamp\_check
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_passwd
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - passwd
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_ssh\_agent
### Title: Record Any Attempts to Run ssh-agent
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_ssh\_keysign
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - ssh-keysign
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_su
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - su
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_sudo
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - sudo
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_sudoedit
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - sudoedit
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_umount
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - umount
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_unix\_update
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - unix\_update
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
       
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_privileged\_commands\_usermod
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - usermod
### Description:

```


At a minimum, the audit system should collect the execution of privileged
commands for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add
a line of the following form to a file with suffix .rules
in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the
following form to /etc/audit/audit.rules:
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_audit\_rules\_time\_watch\_localtime
### Title: Record Attempts to Alter the localtime File
### Description:

```



If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following lines to a file with suffix .rules in the
directory /etc/audit/rules.d:

-w /etc/localtime -p wa -k audit_time_rules

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules:

-w /etc/localtime -p wa -k audit_time_rules
       
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
The Ubuntu 24.04 operating system must allocate audit record storage
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
mode for corrective action. Acceptable values also include

syslog, single and halt

For certain systems, the need for availability
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
mode for corrective action. Acceptable values also include

single and halt

For certain systems, the need for availability
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_auditd\_offload\_logs
### Title: Offload audit Logs to External Media
### Description:

```
The operating system must have a crontab script running weekly to
offload audit events of standalone systems.
```

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_groupownership\_audit\_binaries
### Title: Verify that audit tools are owned by group root
### Description:

```
The Ubuntu 24.04 operating system audit tools must have the proper
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

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_ownership\_audit\_binaries
### Title: Verify that audit tools are owned by root
### Description:

```
The Ubuntu 24.04 operating system audit tools must have the proper
ownership configured to protected against unauthorized access.

Verify it by running the following command:
$ stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd /sbin/augenrules /sbin/audisp-syslog

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

## Rule id: xccdf\_org.ssgproject.content\_rule\_file\_permissions\_audit\_binaries
### Title: Verify that audit tools Have Mode 0755 or less
### Description:

```
The Ubuntu 24.04 operating system audit tools must have the proper
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
$ sudo chmod 0600 /etc/audit/rules.d/*.rules
      
```


# SEE ALSO
**usg**(8)

# COPYRIGHT
Copyright 2025 Canonical Limited. All rights reserved.

The implementation of DISA-STIG rules, CIS rules, profiles, scripts, and other assets are based on the ComplianceAsCode open source project (https://www.open-scap.org/security-policies/scap-security-guide).

ComplianceAsCode's license file can be found in the /usr/share/ubuntu-scap-security-guides/benchmarks directory.
