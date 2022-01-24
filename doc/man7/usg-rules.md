% USG-RULES(7) usg-benchmarks-\* 1.0.0
% Richard Maciel Costa <richard.maciel.costa@canonical.com>
% September 2021

# NAME
usg-rules - usg rules list and description

# LIST OF RULES AND DESCRIPTIONS
## Rule id: kernel\_module\_cramfs\_disabled
### Title: Disable Mounting of cramfs
### Description:

```
To configure the system to prevent the cramfs
kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:
install cramfs /bin/true
This effectively prevents usage of this uncommon filesystem.

The cramfs filesystem type is a compressed read-only
Linux filesystem embedded in small footprint systems. A
cramfs image can be used without having to first
decompress the image.
```

## Rule id: kernel\_module\_freevxfs\_disabled
### Title: Disable Mounting of freevxfs
### Description:

```
To configure the system to prevent the freevxfs
kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:
install freevxfs /bin/true
This effectively prevents usage of this uncommon filesystem.
```

## Rule id: kernel\_module\_jffs2\_disabled
### Title: Disable Mounting of jffs2
### Description:

```
To configure the system to prevent the jffs2
kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:
install jffs2 /bin/true
This effectively prevents usage of this uncommon filesystem.
```

## Rule id: kernel\_module\_hfs\_disabled
### Title: Disable Mounting of hfs
### Description:

```
To configure the system to prevent the hfs
kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:
install hfs /bin/true
This effectively prevents usage of this uncommon filesystem.
```

## Rule id: kernel\_module\_hfsplus\_disabled
### Title: Disable Mounting of hfsplus
### Description:

```
To configure the system to prevent the hfsplus
kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:
install hfsplus /bin/true
This effectively prevents usage of this uncommon filesystem.
```

## Rule id: kernel\_module\_udf\_disabled
### Title: Disable Mounting of udf
### Description:

```
To configure the system to prevent the udf
kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:
install udf /bin/true
This effectively prevents usage of this uncommon filesystem.

The udf filesystem type is the universal disk format
used to implement the ISO/IEC 13346 and ECMA-167 specifications.
This is an open vendor filesystem type for data storage on a broad
range of media. This filesystem type is neccessary to support
writing DVDs and newer optical disc formats.
```

## Rule id: partition\_for\_tmp
### Title: Ensure /tmp Located On Separate Partition
### Description:

```
The /tmp directory is a world-writable directory used
for temporary file storage. Ensure it has its own partition or
logical volume at installation time, or migrate it using LVM.
```

## Rule id: mount\_option\_tmp\_nodev\_optional
### Title: Add nodev Option to /tmp if it exists
### Description:

```
The nodev mount option can be used to prevent device files from
being created in /tmp. Legitimate character and block devices
should not exist within temporary directories like /tmp.
Add the nodev option to the fourth column of
/etc/fstab for the line which controls mounting of
/tmp.
```

## Rule id: mount\_option\_tmp\_nosuid\_optional
### Title: Add nosuid Option to /tmp if it exists
### Description:

```
The nosuid mount option can be used to prevent
execution of setuid programs in /tmp. The SUID and SGID permissions
should not be required in these world-writable directories.
Add the nosuid option to the fourth column of
/etc/fstab for the line which controls mounting of
/tmp.
```

## Rule id: mount\_option\_tmp\_noexec\_optional
### Title: Add noexec Option to /tmp if it exists
### Description:

```
The noexec mount option can be used to prevent binaries
from being executed out of /tmp.
Add the noexec option to the fourth column of
/etc/fstab for the line which controls mounting of
/tmp.
```

## Rule id: mount\_option\_dev\_shm\_nodev
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

## Rule id: mount\_option\_dev\_shm\_nosuid
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

## Rule id: mount\_option\_dev\_shm\_noexec
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

## Rule id: mount\_option\_var\_tmp\_nodev\_optional
### Title: Add nodev Option to /var/tmp if it exists
### Description:

```
The nodev mount option can be used to prevent device files from
being created in /var/tmp. Legitimate character and block devices
should not exist within temporary directories like /var/tmp.
Add the nodev option to the fourth column of
/etc/fstab for the line which controls mounting of
/var/tmp.
```

## Rule id: mount\_option\_var\_tmp\_nosuid\_optional
### Title: Add nosuid Option to /var/tmp if it exists
### Description:

```
The nosuid mount option can be used to prevent
execution of setuid programs in /var/tmp. The SUID and SGID permissions
should not be required in these world-writable directories.
Add the nosuid option to the fourth column of
/etc/fstab for the line which controls mounting of
/var/tmp.
```

## Rule id: mount\_option\_var\_tmp\_noexec\_optional
### Title: Add noexec Option to /var/tmp if it exists
### Description:

```
The noexec mount option can be used to prevent binaries
from being executed out of /var/tmp.
Add the noexec option to the fourth column of
/etc/fstab for the line which controls mounting of
/var/tmp.
```

## Rule id: mount\_option\_home\_nodev\_optional
### Title: Add nodev Option to /home if it exists
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

## Rule id: dir\_perms\_world\_writable\_sticky\_bits
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

## Rule id: service\_autofs\_disabled
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

## Rule id: kernel\_module\_usb-storage\_disabled
### Title: Disable Modprobe Loading of USB Storage Driver
### Description:

```
To prevent USB storage devices from being used, configure the kernel module loading system
to prevent automatic loading of the USB storage driver.

To configure the system to prevent the usb-storage
kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:
install usb-storage /bin/true
This will prevent the modprobe program from loading the usb-storage
module, but will not prevent an administrator (or another program) from using the
insmod program to load the module manually.
```

## Rule id: package\_sudo\_installed
### Title: Install sudo Package
### Description:

```
The sudo package can be installed with the following command:

$ apt-get install sudo
```

## Rule id: sudo\_add\_use\_pty
### Title: Ensure Only Users Logged In To Real tty Can Execute Sudo - sudo use\_pty
### Description:

```
The sudo use_pty tag, when specified, will only execute sudo
commands from users logged in to a real tty.
This should be enabled by making sure that the use_pty tag exists in
/etc/sudoers configuration file or any sudo configuration snippets
in /etc/sudoers.d/.
```

## Rule id: sudo\_custom\_logfile
### Title: Ensure Sudo Logfile Exists - sudo logfile
### Description:

```
A custom log sudo file can be configured with the 'logfile' tag. This rule configures
a sudo custom logfile at the default location suggested by CIS, which uses
/var/log/sudo.log.
```

## Rule id: package\_aide\_installed
### Title: Install AIDE
### Description:

```
The aide package can be installed with the following command:

$ apt-get install aide
```

## Rule id: aide\_build\_database
### Title: Build and Test AIDE Database
### Description:

```
Run the following command to generate a new database:
$ sudo /usr/sbin/aide --init
By default, the database will be written to the file /var/lib/aide/aide.db.new.gz.
Storing the database, the configuration file /etc/aide.conf, and the binary
/usr/sbin/aide (or hashes of these files), in a secure location (such as on read-only media) provides additional assurance about their integrity.
The newly-generated database can be installed as follows:

$ sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

To initiate a manual check, run the following command:
$ sudo /usr/sbin/aide --check
If this check produces any unexpected output, investigate.
```

## Rule id: aide\_periodic\_cron\_checking
### Title: Configure Periodic Execution of AIDE
### Description:

```
At a minimum, AIDE should be configured to run a weekly scan.
To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab:
05 4 * * * root /usr/sbin/aide --check
To implement a weekly execution of AIDE at 4:05am using cron, add the following line to /etc/crontab:
05 4 * * 0 root /usr/sbin/aide --check
AIDE can be executed periodically through other means; this is merely one example.
The usage of cron's special time codes, such as  @daily and
@weekly is acceptable.
```

## Rule id: grub2\_password
### Title: Set Boot Loader Password in grub2
### Description:

```
The grub2 boot loader should have a superuser account and password
protection enabled to protect boot-time settings.

Since plaintext passwords are a security risk, generate a hash for the password
by running the following command:

$ grub2-mkpasswd-pbkdf2

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
grub2-mkconfig -o /boot/grub/grub.cfg
```

## Rule id: file\_owner\_grub2\_cfg
### Title: Verify /boot/grub/grub.cfg User Ownership
### Description:

```
The file /boot/grub/grub.cfg should
be owned by the root user to prevent destruction
or modification of the file.

To properly set the owner of {{{ grub2_boot_path }}}/grub.cfg, run the command:
$ sudo chown root {{{ grub2_boot_path }}}/grub.cfg 
```

## Rule id: file\_permissions\_grub2\_cfg
### Title: Verify /boot/grub/grub.cfg Permissions
### Description:

```
File permissions for /boot/grub/grub.cfg should be set to 600.

To properly set the permissions of {{{ grub2_boot_path }}}/grub.cfg, run the command:
$ sudo chmod 600 {{{ grub2_boot_path }}}/grub.cfg
```

## Rule id: single\_user\_authentication
### Title: Ensure authentication required for single user mode
### Description:

```
Single user mode is used for recovery when the system detects an issue
during boot or by manual selection from the bootloader.
```

## Rule id: ensure\_xd\_nx\_support\_enabled
### Title: Ensure XD/NX support is enabled
### Description:

```
Recent processors in the x86 family support the ability to prevent code
execution on a per memory page basis. Generically and on AMD processors,
this ability is called No Execute (NX), while on Intel processors it is
called Execute Disable (XD). This ability can help prevent exploitation of
buffer overflow vulnerabilities and should be activated whenever possible.
Extra steps must be taken to ensure that this protection is enabled,
particularly on 32-bit x86 systems. Other processors, such as Itanium and
POWER, have included such support since inception and the standard kernel
for those platforms supports the feature.

Note: Ensure your system supports the XD or NX bit and has PAE support
before implementing this recommendation as this may prevent it from
booting if these are not supported by your hardware.
```

## Rule id: sysctl\_kernel\_randomize\_va\_space
### Title: Enable Randomized Layout of Virtual Address Space
### Description:

```
To set the runtime status of the kernel.randomize_va_space kernel parameter, run the following command: $ sudo sysctl -w kernel.randomize_va_space=2
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: kernel.randomize_va_space = 2
```

## Rule id: package\_prelink\_removed
### Title: Disable Prelinking via removing prelink package
### Description:

```
The prelinking feature changes binaries in an attempt to decrease their startup
time. In order to disable it, run the following command to return binaries to a
normal, non-prelinked state:
$ sudo /usr/sbin/prelink -ua
Then remove the prelink package.
```

## Rule id: service\_apport\_disabled
### Title: Disable Apport Service
### Description:

```
The Apport modifies certain kernel configuration values at
runtime which may decrease the overall security of the system and expose sensitive data.

The apport service can be disabled with the following command:
$ sudo systemctl mask --now apport.service
```

## Rule id: disable\_users\_coredumps
### Title: Disable Core Dumps for All Users
### Description:

```
To disable core dumps for all users, add the following line to
/etc/security/limits.conf, or to a file within the
/etc/security/limits.d/ directory:
*     hard   core    0
```

## Rule id: sysctl\_fs\_suid\_dumpable
### Title: Disable Core Dumps for SUID programs
### Description:

```
To set the runtime status of the fs.suid_dumpable kernel parameter, run the following command: $ sudo sysctl -w fs.suid_dumpable=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: fs.suid_dumpable = 0
```

## Rule id: package\_apparmor\_installed
### Title: Ensure AppArmor is installed
### Description:

```
AppArmor provide Mandatory Access Controls.
```

## Rule id: grub2\_enable\_apparmor
### Title: Ensure AppArmor is enabled in the bootloader configuration
### Description:

```
Configure AppArmor to be enabled at boot time and verify that it has not been
overwritten by the bootloader boot parameters.

Note: This recommendation is designed around the grub bootloader, if LILO or
another bootloader is in use in your environment, enact equivalent settings.
```

## Rule id: ensure\_apparmor\_enforce\_or\_complain
### Title: Ensure all AppArmor Profiles are in enforce or complain mode
### Description:

```
AppArmor profiles define what resources applications are able to access.
```

## Rule id: no\_etc\_motd\_leak
### Title: Ensure message of the day is configured properly
### Description:

```
The contents of the /etc/motd file are displayed to users after login and function as a
message of the day for authenticated users.

Unix-based systems have typically displayed information about the OS release and patch
level upon logging in to the system. This information can be useful to developers who are
developing software for a particular OS platform. If mingetty(8) supports the following
options, they display operating system information: \m - machine architecture \r -
operating system release \s - operating system name \v - operating system version.
```

## Rule id: no\_etc\_issue\_leak
### Title: Ensure local login warning banner is configured properly
### Description:

```
The contents of the /etc/issue file are displayed to users priorto login for
local terminals.

Unix-based systems have typically displayed information
about the OS release and patch level upon logging in to the system. This
information can be useful to developers who are developing software for a
particular OS platform. If mingetty(8) supports the following options, they
display operating system information: \m - machine architecture \r -
operating system release \s - operating system name \v - operating system
version
```

## Rule id: no\_etc\_issue\_net\_leak
### Title: Ensure remote login warning banner is configured properly
### Description:

```
The contents of the /etc/issue.net file are displayed to users prior to login
for remote connections from configured services.

Unix-based systems have typically displayed information about the OS release
and patch level upon logging in to the system. This information can be useful
to developers who are developing software for a particular OS platform. If mingetty(8)
supports the following options, they display operating system information:
\m - machine architecture \r - operating system release \s - operating
system name \v - operating system version
```

## Rule id: file\_permissions\_etc\_motd
### Title: Verify permissions on Message of the Day Banner
### Description:

```
To properly set the permissions of /etc/motd, run the command:
$ sudo chmod 0644 /etc/motd
```

## Rule id: file\_owner\_etc\_motd
### Title: Verify ownership of Message of the Day Banner
### Description:

```
To properly set the owner of /etc/motd, run the command:
$ sudo chown root /etc/motd 
```

## Rule id: file\_groupowner\_etc\_motd
### Title: Verify Group Ownership of Message of the Day Banner
### Description:

```
To properly set the group owner of /etc/motd, run the command:
$ sudo chgrp root /etc/motd
```

## Rule id: file\_permissions\_etc\_issue
### Title: Verify permissions on System Login Banner
### Description:

```
To properly set the permissions of /etc/issue, run the command:
$ sudo chmod 0644 /etc/issue
```

## Rule id: file\_owner\_etc\_issue
### Title: Verify ownership of System Login Banner
### Description:

```
To properly set the owner of /etc/issue, run the command:
$ sudo chown root /etc/issue 
```

## Rule id: file\_groupowner\_etc\_issue
### Title: Verify Group Ownership of System Login Banner
### Description:

```
To properly set the group owner of /etc/issue, run the command:
$ sudo chgrp root /etc/issue
```

## Rule id: file\_permissions\_etc\_issue\_net
### Title: Verify permissions on Remote Login Banner
### Description:

```
To properly set the permissions of /etc/issue.net, run the command:
$ sudo chmod 0644 /etc/issue.net
```

## Rule id: file\_owner\_etc\_issue\_net
### Title: Verify ownership of Remote Login Banner
### Description:

```
To properly set the owner of /etc/issue.net, run the command:
$ sudo chown root /etc/issue.net 
```

## Rule id: file\_groupowner\_etc\_issue\_net
### Title: Verify Group Ownership of Remote Login Banner
### Description:

```
To properly set the group owner of /etc/issue.net, run the command:
$ sudo chgrp root /etc/issue.net
```

## Rule id: package\_gdm\_removed
### Title: Remove the GDM Package Group
### Description:

```
By removing the gdm3 package, the system no longer has GNOME installed

installed. If X Windows is not installed then the system cannot boot into graphical user mode.
This prevents the system from being accidentally or maliciously booted into a graphical.target
mode. To do so, run the following command:

$ sudo apt remove gdm3
```

## Rule id: enable\_dconf\_user\_profile
### Title: Configure GNOME3 DConf User Profile
### Description:

```
By default, DConf provides a standard user profile. This profile contains a list
of DConf configuration databases. The user profile and database always take the
highest priority. As such the DConf User profile should always exist and be
configured correctly.


To make sure that the user profile is configured correctly, the /etc/dconf/profile/gdm
should be set as follows:
user-db:user
system-db:gdm

```

## Rule id: dconf\_gnome\_banner\_enabled
### Title: Enable GNOME3 Login Warning Banner
### Description:

```
In the default graphical environment, displaying a login warning banner
in the GNOME Display Manager's login screen can be enabled on the login
screen by setting banner-message-enable to true.

To enable, add or edit banner-message-enable to

/etc/gdm3/greeter.dconf-defaults. For example:
[org/gnome/login-screen]
banner-message-enable=true


After the settings have been set, run dconf update.
The banner text must also be set.
```

## Rule id: dconf\_gnome\_login\_banner\_text
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

## Rule id: dconf\_gnome\_disable\_user\_list
### Title: Disable the GNOME3 Login User List
### Description:

```
In the default graphical environment, users logging directly into the
system are greeted with a login screen that displays all known users.
This functionality should be disabled by setting disable-user-list
to true.

To disable, add or edit disable-user-list to

/etc/gdm3/greeter.dconf-defaults. For example:
[org/gnome/login-screen]
disable-user-list=true


After the settings have been set, run dconf update.
```

## Rule id: package\_xinetd\_removed
### Title: Uninstall xinetd Package
### Description:

```
The xinetd package can be removed with the following command:

$ apt-get remove xinetd
```

## Rule id: package\_openbsd-inetd\_removed
### Title: Uninstall openbsd-inetd Package
### Description:

```
The openbsd-inetd package can be removed with the following command:

$ apt-get remove openbsd-inetd
```

## Rule id: package\_chrony\_installed
### Title: The Chrony package is installed
### Description:

```
System time should be synchronized between all systems in an environment. This is
typically done by establishing an authoritative time server or set of servers and having all
systems synchronize their clocks to them.
The chrony package can be installed with the following command:

$ apt-get install chrony
```

## Rule id: package\_ntp\_removed
### Title: Remove the ntp package
### Description:

```
The ntpd service should be removed.
```

## Rule id: service\_chrony\_enabled
### Title: Enable the Chrony Daemon
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

## Rule id: chronyd\_run\_as\_chrony\_user
### Title: Ensure that chronyd is running under chrony user account
### Description:

```
chrony is a daemon which implements the Network Time Protocol (NTP). It is designed to
synchronize system clocks across a variety of systems and use a source that is highly
accurate. More information on chrony can be found at

    http://chrony.tuxfamily.org/.
Chrony can be configured to be a client and/or a server.
To ensure that chronyd is running under chrony user account, Add or edit the

user variable in /etc/chrony/chrony.conf is set to _chrony or is
absent:
user _chrony

This recommendation only applies if chrony is in use on the system.
```

## Rule id: chronyd\_specify\_remote\_server
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

## Rule id: package\_ntp\_installed
### Title: Install the ntp service
### Description:

```
The ntpd service should be installed.
```

## Rule id: package\_chrony\_removed
### Title: The Chrony package is removed
### Description:

```
System time should be synchronized between all systems in an environment. This is
typically done by establishing an authoritative time server or set of servers and having all
systems synchronize their clocks to them.
The chrony package can be removed with the following command:

$ apt-get remove chrony
```

## Rule id: service\_ntp\_enabled
### Title: Enable the NTP Daemon
### Description:

```
The ntpd service can be enabled with the following command:
$ sudo systemctl enable ntpd.service
```

## Rule id: package\_xorg-x11-server-common\_removed
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

## Rule id: service\_avahi-daemon\_disabled
### Title: Disable Avahi Server Software
### Description:

```
The avahi-daemon service can be disabled with the following command:
$ sudo systemctl mask --now avahi-daemon.service
```

## Rule id: package\_avahi-daemon\_removed
### Title: Uninstall avahi-daemon Package
### Description:

```
The avahi-daemon package can be removed with the following command:

$ apt-get remove avahi-daemon
```

## Rule id: service\_cups\_disabled
### Title: Disable the CUPS Service
### Description:

```
The cups service can be disabled with the following command:
$ sudo systemctl mask --now cups.service
```

## Rule id: package\_cups\_removed
### Title: Uninstall cups Package
### Description:

```
The cups package can be removed with the following command:

$ apt-get remove cups
```

## Rule id: package\_dhcp\_removed
### Title: Uninstall DHCP Server Package
### Description:

```
If the system does not need to act as a DHCP server,
the dhcp package can be uninstalled.

The isc-dhcp-server package can be removed with the following command:

$ apt-get remove isc-dhcp-server
```

## Rule id: package\_openldap-servers\_removed
### Title: Uninstall openldap-servers Package
### Description:

```
The slapd package is not installed by default on a Ubuntu 20.04

system. It is needed only by the OpenLDAP server, not by the
clients which use LDAP for authentication. If the system is not
intended for use as an LDAP Server it should be removed.
```

## Rule id: package\_nfs-kernel-server\_removed
### Title: Uninstall nfs-kernel-server Package
### Description:

```
The nfs-kernel-server package can be removed with the following command:

$ apt-get remove nfs-kernel-server
```

## Rule id: package\_bind\_removed
### Title: Uninstall bind Package
### Description:

```
The named service is provided by the bind package.
The bind package can be removed with the following command:

$ apt-get remove bind
```

## Rule id: package\_vsftpd\_removed
### Title: Uninstall vsftpd Package
### Description:

```
The vsftpd package can be removed with the following command:  $ apt-get remove vsftpd
```

## Rule id: package\_httpd\_removed
### Title: Uninstall httpd Package
### Description:

```
The apache2 package can be removed with the following command:

$ apt-get remove apache2
```

## Rule id: package\_dovecot\_removed
### Title: Uninstall dovecot Package
### Description:

```
The dovecot-core package can be removed with the following command:

$ apt-get remove dovecot-core
```

## Rule id: package\_samba\_removed
### Title: Uninstall Samba Package
### Description:

```
The samba package can be removed with the following command:  $ apt-get remove samba
```

## Rule id: package\_squid\_removed
### Title: Uninstall squid Package
### Description:

```
The squid package can be removed with the following command:  $ apt-get remove squid
```

## Rule id: package\_net-snmp\_removed
### Title: Uninstall net-snmp Package
### Description:

```
The snmp package provides the snmpd service.
The snmp package can be removed with the following command:

$ apt-get remove snmp
```

## Rule id: postfix\_network\_listening\_disabled
### Title: Disable Postfix Network Listening
### Description:

```
Edit the file /etc/postfix/main.cf to ensure that only the following
inet_interfaces line appears:
inet_interfaces = <value of var_postfix_inet_interfaces variable>
```

## Rule id: has\_nonlocal\_mta
### Title: Ensure mail transfer agent is configured for local-only mode
### Description:

```
Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming
mail and transfer the messages to the appropriate user or mail server. If the system is not
intended to be a mail server, it is recommended that the MTA be configured to only process
local mail.
```

## Rule id: package\_rsync\_removed
### Title: Uninstall rsync Package
### Description:

```
The rsync package can be removed with the following command:

$ apt-get remove rsync
```

## Rule id: package\_nis\_removed
### Title: Uninstall the nis package
### Description:

```
The support for Yellowpages should not be installed unless it is required.
```

## Rule id: package\_rsh\_removed
### Title: Uninstall rsh Package
### Description:

```
The rsh-client package contains the client commands

for the rsh services
```

## Rule id: package\_talk\_removed
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

## Rule id: package\_telnet\_removed
### Title: Remove telnet Clients
### Description:

```
The telnet client allows users to start connections to other systems via
the telnet protocol.
```

## Rule id: package\_openldap-clients\_removed
### Title: Ensure LDAP client is not installed
### Description:

```
The Lightweight Directory Access Protocol (LDAP) is a service that provides
a method for looking up information from a central database.
The openldap-clients package can be removed with the following command:

$ apt-get remove openldap-clients
```

## Rule id: package\_rpcbind\_removed
### Title: Uninstall rpcbind Package
### Description:

```
The rpcbind package can be removed with the following command:

$ apt-get remove rpcbind
```

## Rule id: wireless\_disable\_interfaces
### Title: Deactivate Wireless Network Interfaces
### Description:

```
Deactivating wireless network interfaces should prevent
normal usage of the wireless capability.


Verify that there are no wireless interfaces configured on the system
with the following command:
$ ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename
For each interface, configure the system to disable wireless network
interfaces with the following command:
$ sudo ifdown 
For each interface listed, find their respective module with the
following command:
$ basename $(readlink -f /sys/class/net/
where interface name must be substituted by the actual interface name.
Create a file in the /etc/modprobe.d directory and for each module,
add the following line:
install 
For each module from the system, execute the following command to
remove it:
$ sudo modprobe -r 
```

## Rule id: sysctl\_net\_ipv4\_conf\_all\_send\_redirects
### Title: Disable Kernel Parameter for Sending ICMP Redirects on all IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.send_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.send_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.send_redirects = 0
```

## Rule id: sysctl\_net\_ipv4\_conf\_default\_send\_redirects
### Title: Disable Kernel Parameter for Sending ICMP Redirects on all IPv4 Interfaces by Default
### Description:

```
To set the runtime status of the net.ipv4.conf.default.send_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.send_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.send_redirects = 0
```

## Rule id: sysctl\_net\_ipv4\_ip\_forward
### Title: Disable Kernel Parameter for IP Forwarding on IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.ip_forward kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.ip_forward=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.ip_forward = 0
```

## Rule id: sysctl\_net\_ipv6\_conf\_all\_forwarding
### Title: Disable Kernel Parameter for IPv6 Forwarding
### Description:

```
To set the runtime status of the net.ipv6.conf.all.forwarding kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.all.forwarding=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.all.forwarding = 0
```

## Rule id: sysctl\_net\_ipv4\_conf\_all\_accept\_source\_route
### Title: Disable Kernel Parameter for Accepting Source-Routed Packets on all IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.accept_source_route kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.accept_source_route = 0
```

## Rule id: sysctl\_net\_ipv4\_conf\_default\_accept\_source\_route
### Title: Disable Kernel Parameter for Accepting Source-Routed Packets on IPv4 Interfaces by Default
### Description:

```
To set the runtime status of the net.ipv4.conf.default.accept_source_route kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.accept_source_route=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.accept_source_route = 0
```

## Rule id: sysctl\_net\_ipv6\_conf\_all\_accept\_source\_route
### Title: Disable Kernel Parameter for Accepting Source-Routed Packets on all IPv6 Interfaces
### Description:

```
To set the runtime status of the net.ipv6.conf.all.accept_source_route kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.all.accept_source_route=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.all.accept_source_route = 0
```

## Rule id: sysctl\_net\_ipv6\_conf\_default\_accept\_source\_route
### Title: Disable Kernel Parameter for Accepting Source-Routed Packets on IPv6 Interfaces by Default
### Description:

```
To set the runtime status of the net.ipv6.conf.default.accept_source_route kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.default.accept_source_route=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.default.accept_source_route = 0
```

## Rule id: sysctl\_net\_ipv4\_conf\_all\_accept\_redirects
### Title: Disable Accepting ICMP Redirects for All IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.accept_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.accept_redirects = 0
```

## Rule id: sysctl\_net\_ipv4\_conf\_default\_accept\_redirects
### Title: Disable Kernel Parameter for Accepting ICMP Redirects by Default on IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.default.accept_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.accept_redirects = 0
```

## Rule id: sysctl\_net\_ipv6\_conf\_all\_accept\_redirects
### Title: Disable Accepting ICMP Redirects for All IPv6 Interfaces
### Description:

```
To set the runtime status of the net.ipv6.conf.all.accept_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.all.accept_redirects = 0
```

## Rule id: sysctl\_net\_ipv6\_conf\_default\_accept\_redirects
### Title: Disable Kernel Parameter for Accepting ICMP Redirects by Default on IPv6 Interfaces
### Description:

```
To set the runtime status of the net.ipv6.conf.default.accept_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.default.accept_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.default.accept_redirects = 0
```

## Rule id: sysctl\_net\_ipv4\_conf\_all\_secure\_redirects
### Title: Disable Kernel Parameter for Accepting Secure ICMP Redirects on all IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.secure_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.secure_redirects = 0
```

## Rule id: sysctl\_net\_ipv4\_conf\_default\_secure\_redirects
### Title: Configure Kernel Parameter for Accepting Secure Redirects By Default
### Description:

```
To set the runtime status of the net.ipv4.conf.default.secure_redirects kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.secure_redirects = 0
```

## Rule id: sysctl\_net\_ipv4\_conf\_all\_log\_martians
### Title: Enable Kernel Parameter to Log Martian Packets on all IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.log_martians kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.log_martians=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.log_martians = 1
```

## Rule id: sysctl\_net\_ipv4\_conf\_default\_log\_martians
### Title: Enable Kernel Paremeter to Log Martian Packets on all IPv4 Interfaces by Default
### Description:

```
To set the runtime status of the net.ipv4.conf.default.log_martians kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.log_martians=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.log_martians = 1
```

## Rule id: sysctl\_net\_ipv4\_icmp\_echo\_ignore\_broadcasts
### Title: Enable Kernel Parameter to Ignore ICMP Broadcast Echo Requests on IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.icmp_echo_ignore_broadcasts kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.icmp_echo_ignore_broadcasts = 1
```

## Rule id: sysctl\_net\_ipv4\_icmp\_ignore\_bogus\_error\_responses
### Title: Enable Kernel Parameter to Ignore Bogus ICMP Error Responses on IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.icmp_ignore_bogus_error_responses kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.icmp_ignore_bogus_error_responses = 1
```

## Rule id: sysctl\_net\_ipv4\_conf\_all\_rp\_filter
### Title: Enable Kernel Parameter to Use Reverse Path Filtering on all IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.conf.all.rp_filter kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.all.rp_filter=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.all.rp_filter = 1
```

## Rule id: sysctl\_net\_ipv4\_conf\_default\_rp\_filter
### Title: Enable Kernel Parameter to Use Reverse Path Filtering on all IPv4 Interfaces by Default
### Description:

```
To set the runtime status of the net.ipv4.conf.default.rp_filter kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.conf.default.rp_filter=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.conf.default.rp_filter = 1
```

## Rule id: sysctl\_net\_ipv4\_tcp\_syncookies
### Title: Enable Kernel Parameter to Use TCP Syncookies on IPv4 Interfaces
### Description:

```
To set the runtime status of the net.ipv4.tcp_syncookies kernel parameter, run the following command: $ sudo sysctl -w net.ipv4.tcp_syncookies=1
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv4.tcp_syncookies = 1
```

## Rule id: sysctl\_net\_ipv6\_conf\_all\_accept\_ra
### Title: Configure Accepting Router Advertisements on All IPv6 Interfaces
### Description:

```
To set the runtime status of the net.ipv6.conf.all.accept_ra kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.all.accept_ra=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.all.accept_ra = 0
```

## Rule id: sysctl\_net\_ipv6\_conf\_default\_accept\_ra
### Title: Disable Accepting Router Advertisements on all IPv6 Interfaces by Default
### Description:

```
To set the runtime status of the net.ipv6.conf.default.accept_ra kernel parameter, run the following command: $ sudo sysctl -w net.ipv6.conf.default.accept_ra=0
To make sure that the setting is persistent, add the following line to a file in the directory /etc/sysctl.d: net.ipv6.conf.default.accept_ra = 0
```

## Rule id: package\_ufw\_installed
### Title: Install ufw Package
### Description:

```
The ufw package can be installed with the following command:

$ apt-get install ufw
```

## Rule id: package\_iptables-persistent\_removed
### Title: Remove iptables-persistent Package
### Description:

```
The iptables-persistent is a boot-time loader for netfilter rules, iptables plugin.
The iptables-persistent package can be removed with the following command:

$ apt-get remove iptables-persistent
```

## Rule id: service\_ufw\_enabled
### Title: Verify ufw Enabled
### Description:

```
The ufw service can be enabled with the following command:
$ sudo systemctl enable ufw.service
```

## Rule id: ufw\_allow\_in\_lo
### Title: Trafic in on lo is allowed
### Description:

```
UFW should be configured to allow all inbound traffic on the loopback
interface.
```

## Rule id: ufw\_allow\_out\_lo
### Title: Traffic out on lo is allowed
### Description:

```
UFW should be configured to allow all outbound traffic on the loopback
interface.
```

## Rule id: ufw\_deny\_in\_other\_for\_localhost
### Title: Inbound traffic for 127.0.0.0/8 on any other interface is denied.
### Description:

```
UFW should be configured to forbid all traffic for the localhost addresses
(127.0.0.0/8) on interfaces other than the designated lo interface.
```

## Rule id: ufw\_deny\_in\_other\_for\_localhost6
### Title: Inbound traffic for ::1/128 on any other interface is denied.
### Description:

```
UFW should be configured to forbid all traffic for the localhost6 addresses
(::1/128) on interfaces other than the designated lo interface.
```

## Rule id: ufw\_default\_deny
### Title: Ensure default deny firewall policy
### Description:

```
A default deny policy on connections ensures that any unconfigured network usage will be
rejected.

Note: Any port or protocol without a explicit allow before the default deny will be blocked.
```

## Rule id: package\_nftables\_installed
### Title: Install nftables Package
### Description:

```
The nftables package can be installed with the following command:

$ apt-get install nftables
```

## Rule id: package\_ufw\_removed
### Title: Remove ufw Package
### Description:

```
The ufw package can be removed with the following command:

$ apt-get remove ufw
```

## Rule id: nftables\_ensure\_table\_exists
### Title: Ensure a table exists
### Description:

```
Tables hold chains. Each table only has one address family and only applies to packets of
this family. Tables can have one of five families.
```

## Rule id: nftables\_ensure\_base\_chain\_exist
### Title: Ensure base chains exist
### Description:

```
Chains are containers for rules. They exist in two kinds, base chains and regular chains. A
base chain is an entry point for packets from the networking stack, a regular chain may be
used as jump target and is used for better rule organization.
```

## Rule id: nftables\_allow\_in\_lo
### Title: Trafic in on lo is allowed
### Description:

```
nftables should be configured to allow all inbound traffic on the loopback
interface.
```

## Rule id: nftables\_deny\_in\_other\_for\_localhost
### Title: Inbound traffic for 127.0.0.0/8 on any other interface is denied.
### Description:

```
nftables should be configured to forbid all traffic for the localhost addresses
(127.0.0.0/8) on interfaces other than the designated lo interface.
```

## Rule id: nftables\_deny\_in\_other\_for\_localhost6
### Title: Inbound traffic for ::1/128 on any other interface is denied.
### Description:

```
nftables should be configured to forbid all traffic for the localhost6 addresses
(::1/128) on interfaces other than the designated lo interface.
```

## Rule id: nftables\_default\_deny
### Title: Ensure default deny firewall policy
### Description:

```
Base chain policy is the default verdict that will be applied to packets reaching the end of
the chain.
```

## Rule id: service\_nftables\_enabled
### Title: Verify nftables Enabled
### Description:

```
The nftables service can be enabled with the following command:
$ sudo systemctl enable nftables.service
```

## Rule id: nftables\_permanent\_rules
### Title: Ensure nftables rules are permanent
### Description:

```
nftables is a subsystem of the Linux kernel providing filtering and classification of network
packets/datagrams/frames.

The nftables service reads the /etc/nftables.conf file for a nftables file or files to include
in the nftables ruleset.

A nftables ruleset containing the input, forward, and output base chains allow network
traffic to be filtered.
```

## Rule id: package\_iptables\_installed
### Title: Install iptables Package
### Description:

```
The iptables package can be installed with the following command:

$ apt-get install iptables
```

## Rule id: package\_iptables-persistent\_installed
### Title: Install iptables-persistent Package
### Description:

```
The iptables-persistent package can be installed with the following command:

$ apt-get install iptables-persistent
```

## Rule id: package\_nftables\_removed
### Title: Remove nftables Package
### Description:

```
The nftables package can be removed with the following command:

$ apt-get remove nftables
```

## Rule id: iptables\_default\_deny
### Title: Ensure default deny firewall policy
### Description:

```
With a default accept policy the firewall will accept any packet that is not
configured to be denied. It is easier to white list acceptable usage than
to black list unacceptable usage.

Notes:

```

## Rule id: iptables\_allow\_in\_lo
### Title: Trafic in on lo is allowed
### Description:

```
iptables should be configured to allow all inbound traffic on the loopback
interface.
```

## Rule id: iptables\_allow\_out\_lo
### Title: Traffic out on lo is allowed
### Description:

```
iptables should be configured to allow all outbound traffic on the loopback
interface.
```

## Rule id: iptables\_deny\_in\_other\_for\_localhost
### Title: Inbound traffic for 127.0.0.0/8 on any other interface is denied.
### Description:

```
iptables should be configured to forbid all traffic for the localhost addresses
(127.0.0.0/8) on interfaces other than the designated lo interface.
```

## Rule id: ip6tables\_default\_deny
### Title: Ensure default deny firewall policy - iptables6
### Description:

```
With a default accept policy the firewall will accept any packet that is not
configured to be denied. It is easier to white list acceptable usage than
to black list unacceptable usage.

Notes:

```

## Rule id: ip6tables\_allow\_in\_lo
### Title: Trafic in on lo is allowed
### Description:

```
ip6tables should be configured to allow all inbound traffic on the loopback
interface.
```

## Rule id: ip6tables\_allow\_out\_lo
### Title: Traffic out on lo is allowed
### Description:

```
ip6tables should be configured to allow all outbound traffic on the loopback
interface.
```

## Rule id: ip6tables\_deny\_in\_other\_for\_localhost6
### Title: Inbound traffic for ::1/128 on any other interface is denied.
### Description:

```
iptables6 should be configured to forbid all traffic for the localhost6 addresses
(::1/128) on interfaces other than the designated lo interface.
```

## Rule id: package\_rsyslog\_installed
### Title: Ensure rsyslog is Installed
### Description:

```
Rsyslog is installed by default. The rsyslog package can be installed with the following command:  $ apt-get install rsyslog
```

## Rule id: service\_rsyslog\_enabled
### Title: Enable rsyslog Service
### Description:

```
The rsyslog service provides syslog-style logging by default on Ubuntu 20.04.

The rsyslog service can be enabled with the following command:
$ sudo systemctl enable rsyslog.service
```

## Rule id: rsyslog\_filecreatemode
### Title: Ensure rsyslog default file permissions configured
### Description:

```
rsyslog will create logfiles that do not already exist on the system. This setting controls
what permissions will be applied to these newly created files.
```

## Rule id: rsyslog\_remote\_loghost
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

## Rule id: forward\_to\_syslog
### Title: Ensure journald is configured to send logs to rsyslog
### Description:

```
Data from journald may be stored in volatile memory or persisted locally on the server.
Utilities exist to accept remote export of journald logs, however, use of the rsyslog service
provides a consistent means of log collection and export.

Notes:
 - This recommendation assumes that recommendation 4.2.1.5, "Ensure rsyslog is
   configured to send logs to a remote log host" has been implemented.
 - As noted in the journald man pages, journald logs may be exported to rsyslog either
   through the process mentioned here, or through a facility like systemd-
   journald.service . There are trade-offs involved in each implementation, where
   ForwardToSyslog will immediately capture all events (and forward to an external log
   server, if properly configured), but may not capture all boot-up activities. Mechanisms
   such as systemd-journald.service , on the other hand, will record bootup events, but
   may delay sending the information to rsyslog, leading to the potential for log
   manipulation prior to export. Be aware of the limitations of all tools employed to
   secure a system.
 - The main configuration file /etc/systemd/journald.conf is read before any of the
   custom *.conf files. If there are custom configs present, they override the main
   configuration parameters.
```

## Rule id: compress\_large\_logs
### Title: Ensure journald is configured to compress large log files
### Description:

```
The journald system includes the capability of compressing overly large files to avoid filling
up the system with logs or making the logs unmanageably large.

Note: The main configuration file /etc/systemd/journald.conf is read before any of the
custom *.conf files. If there are custom configs present, they override the main configuration
parameters.
```

## Rule id: persistent\_storage
### Title: Ensure journald is configured to write logfiles to persistent disk
### Description:

```
Data from journald may be stored in volatile memory or persisted locally on the server.
Logs in memory will be lost upon a system reboot. By persisting logs to local disk on the
server they are protected from loss.

Note: The main configuration file /etc/systemd/journald.conf is read before any of the
custom *.conf files. If there are custom configs present, they override the main configuration
parameters.
```

## Rule id: all\_logfile\_permissions
### Title: Ensure permissions on all logfiles are configured
### Description:

```
Log files stored in /var/log/ contain logged information from many services on the system,
or on log hosts others as well.

Note: You may also need to change the configuration for your logging software or services for
any logs that had incorrect permissions.
```

## Rule id: ensure\_logrotate\_permissions
### Title: Ensure logrotate assigns appropriate permissions
### Description:

```
Log files contain logged information from many services on the system, or on log hosts
others as well.
```

## Rule id: service\_cron\_enabled
### Title: Enable cron Service
### Description:

```
The crond service is used to execute commands at
preconfigured times. It is required by almost all systems to perform necessary
maintenance tasks, such as notifying root of system activity.

The cron service can be enabled with the following command:
$ sudo systemctl enable cron.service
```

## Rule id: file\_permissions\_crontab
### Title: Verify Permissions on crontab
### Description:

```
To properly set the permissions of /etc/crontab, run the command:
$ sudo chmod 0600 /etc/crontab
```

## Rule id: file\_owner\_crontab
### Title: Verify Owner on crontab
### Description:

```
To properly set the owner of /etc/crontab, run the command:
$ sudo chown root /etc/crontab 
```

## Rule id: file\_groupowner\_crontab
### Title: Verify Group Who Owns Crontab
### Description:

```
To properly set the group owner of /etc/crontab, run the command:
$ sudo chgrp root /etc/crontab
```

## Rule id: file\_permissions\_cron\_hourly
### Title: Verify Permissions on cron.hourly
### Description:

```
To properly set the permissions of /etc/cron.hourly, run the command:
$ sudo chmod 0700 /etc/cron.hourly
```

## Rule id: file\_owner\_cron\_hourly
### Title: Verify Owner on cron.hourly
### Description:

```
To properly set the owner of /etc/cron.hourly, run the command:
$ sudo chown root /etc/cron.hourly 
```

## Rule id: file\_groupowner\_cron\_hourly
### Title: Verify Group Who Owns cron.hourly
### Description:

```
To properly set the group owner of /etc/cron.hourly, run the command:
$ sudo chgrp root /etc/cron.hourly
```

## Rule id: file\_permissions\_cron\_daily
### Title: Verify Permissions on cron.daily
### Description:

```
To properly set the permissions of /etc/cron.daily, run the command:
$ sudo chmod 0700 /etc/cron.daily
```

## Rule id: file\_owner\_cron\_daily
### Title: Verify Owner on cron.daily
### Description:

```
To properly set the owner of /etc/cron.daily, run the command:
$ sudo chown root /etc/cron.daily 
```

## Rule id: file\_groupowner\_cron\_daily
### Title: Verify Group Who Owns cron.daily
### Description:

```
To properly set the group owner of /etc/cron.daily, run the command:
$ sudo chgrp root /etc/cron.daily
```

## Rule id: file\_permissions\_cron\_weekly
### Title: Verify Permissions on cron.weekly
### Description:

```
To properly set the permissions of /etc/cron.weekly, run the command:
$ sudo chmod 0700 /etc/cron.weekly
```

## Rule id: file\_owner\_cron\_weekly
### Title: Verify Owner on cron.weekly
### Description:

```
To properly set the owner of /etc/cron.weekly, run the command:
$ sudo chown root /etc/cron.weekly 
```

## Rule id: file\_groupowner\_cron\_weekly
### Title: Verify Group Who Owns cron.weekly
### Description:

```
To properly set the group owner of /etc/cron.weekly, run the command:
$ sudo chgrp root /etc/cron.weekly
```

## Rule id: file\_permissions\_cron\_monthly
### Title: Verify Permissions on cron.monthly
### Description:

```
To properly set the permissions of /etc/cron.monthly, run the command:
$ sudo chmod 0700 /etc/cron.monthly
```

## Rule id: file\_owner\_cron\_monthly
### Title: Verify Owner on cron.monthly
### Description:

```
To properly set the owner of /etc/cron.monthly, run the command:
$ sudo chown root /etc/cron.monthly 
```

## Rule id: file\_groupowner\_cron\_monthly
### Title: Verify Group Who Owns cron.monthly
### Description:

```
To properly set the group owner of /etc/cron.monthly, run the command:
$ sudo chgrp root /etc/cron.monthly
```

## Rule id: file\_permissions\_cron\_d
### Title: Verify Permissions on cron.d
### Description:

```
To properly set the permissions of /etc/cron.d, run the command:
$ sudo chmod 0700 /etc/cron.d
```

## Rule id: file\_owner\_cron\_d
### Title: Verify Owner on cron.d
### Description:

```
To properly set the owner of /etc/cron.d, run the command:
$ sudo chown root /etc/cron.d 
```

## Rule id: file\_groupowner\_cron\_d
### Title: Verify Group Who Owns cron.d
### Description:

```
To properly set the group owner of /etc/cron.d, run the command:
$ sudo chgrp root /etc/cron.d
```

## Rule id: restrict\_cron\_users
### Title: Ensure cron is restricted to authorized users
### Description:

```
Configure /etc/cron.allow to allow specific users to use these services. If
/etc/cron.allow do not exist, then /etc/cron.deny is checked. Any user not
specifically defined in these file is allowed to use cron. By removing the
file, only users in /etc/cron.allow is allowed to use cron.

Notes:
 - Other methods, such as systemd timers, exist for scheduling jobs. If another method is
   used, cron should be removed, and the alternate method should be secured in
   accordance with local site policy.
 - Even though a given user is not listed in cron.allow, cron jobs can still be run as that
   user.
 - The cron.allow file only controls administrative access to the crontab command for
   scheduling and modifying cron jobs.
```

## Rule id: file\_permissions\_cron\_allow
### Title: Verify Permissions on /etc/cron.allow file
### Description:

```
If /etc/cron.allow exists, it must have permissions 0640
or more restrictive.


To properly set the permissions of /etc/cron.allow, run the command:
$ sudo chmod 0640 /etc/cron.allow
```

## Rule id: file\_owner\_cron\_allow
### Title: Verify User Who Owns /etc/cron.allow file
### Description:

```
If /etc/cron.allow exists, it must be owned by root.

To properly set the owner of /etc/cron.allow, run the command:
$ sudo chown root /etc/cron.allow 
```

## Rule id: file\_groupowner\_cron\_allow
### Title: Verify Group Who Owns /etc/cron.allow file
### Description:

```
If /etc/cron.allow exists, it must be group-owned by root.

To properly set the group owner of /etc/cron.allow, run the command:
$ sudo chgrp root /etc/cron.allow
```

## Rule id: restrict\_at\_users
### Title: Ensure at is restricted to authorized users
### Description:

```
Configure /etc/at.allow to allow specific users to use these services. If
/etc/at.allow do not exist, then /etc/at.deny is checked. Any user not
specifically defined in these file is allowed to use at. By removing the
file, only users in /etc/at.allow is allowed to use at.

Note: Other methods, such as systemd timers , exist for scheduling jobs. If another method is
used, at should be removed, and the alternate method should be secured in accordance with
local site policy.
```

## Rule id: file\_permissions\_at\_allow
### Title: Verify Permissions on /etc/at.allow file
### Description:

```
If /etc/at.allow exists, it must have permissions 0640
or more restrictive.


To properly set the permissions of /etc/at.allow, run the command:
$ sudo chmod 0640 /etc/at.allow
```

## Rule id: file\_owner\_at\_allow
### Title: Verify User Who Owns /etc/at.allow file
### Description:

```
If /etc/at.allow exists, it must be owned by root.

To properly set the owner of /etc/at.allow, run the command:
$ sudo chown root /etc/at.allow 
```

## Rule id: file\_groupowner\_at\_allow
### Title: Verify Group Who Owns /etc/at.allow file
### Description:

```
If /etc/at.allow exists, it must be group-owned by root.

To properly set the group owner of /etc/at.allow, run the command:
$ sudo chgrp root /etc/at.allow
```

## Rule id: file\_permissions\_sshd\_config
### Title: Verify Permissions on SSH Server config file
### Description:

```
To properly set the permissions of /etc/ssh/sshd_config, run the command:
$ sudo chmod 0600 /etc/ssh/sshd_config
```

## Rule id: file\_owner\_sshd\_config
### Title: Verify Owner on SSH Server config file
### Description:

```
To properly set the owner of /etc/ssh/sshd_config, run the command:
$ sudo chown root /etc/ssh/sshd_config 
```

## Rule id: file\_groupowner\_sshd\_config
### Title: Verify Group Who Owns SSH Server config file
### Description:

```
To properly set the group owner of /etc/ssh/sshd_config, run the command:
$ sudo chgrp root /etc/ssh/sshd_config
```

## Rule id: file\_permissions\_sshd\_private\_key
### Title: Verify Permissions on SSH Server Private \*\_key Key Files
### Description:

```

To properly set the permissions of /etc/ssh/*_key, run the command:
$ sudo chmod 0640 /etc/ssh/*_key
```

## Rule id: file\_permissions\_sshd\_pub\_key
### Title: Verify Permissions on SSH Server Public \*.pub Key Files
### Description:

```
 To properly set the permissions of /etc/ssh/*.pub, run the command: $ sudo chmod 0644 /etc/ssh/*.pub
```

## Rule id: sshd\_set\_loglevel\_info\_or\_verbose
### Title: Set LogLevel to INFO or VERBOSE
### Description:

```
The LogLevel parameter specifices that record login and logout activity will be logged.
To specify the log level in
SSH, add or correct the following line in the /etc/ssh/sshd_config file:
LogLevel INFO or LogLevel INFO
```

## Rule id: sshd\_set\_max\_auth\_tries
### Title: Set SSH authentication attempt limit
### Description:

```
The MaxAuthTries parameter specifies the maximum number of authentication attempts
permitted per connection. Once the number of failures reaches half this value, additional failures are logged.
to set MaxAUthTries edit /etc/ssh/sshd_config as follows:
MaxAuthTries 
```

## Rule id: sshd\_disable\_rhosts
### Title: Disable SSH Support for .rhosts Files
### Description:

```
SSH can emulate the behavior of the obsolete rsh
command in allowing users to enable insecure access to their
accounts via .rhosts files.

To ensure this behavior is disabled, add or correct the
following line in /etc/ssh/sshd_config:
IgnoreRhosts yes
```

## Rule id: disable\_host\_auth
### Title: Disable Host-Based Authentication
### Description:

```
SSH's cryptographic host-based authentication is
more secure than .rhosts authentication. However, it is
not recommended that hosts unilaterally trust one another, even
within an organization.

To disable host-based authentication, add or correct the
following line in /etc/ssh/sshd_config:
HostbasedAuthentication no
```

## Rule id: sshd\_disable\_root\_login
### Title: Disable SSH Root Login
### Description:

```
The root user should never be allowed to login to a
system directly over a network.
To disable root login via SSH, add or correct the following line
in /etc/ssh/sshd_config:
PermitRootLogin no
```

## Rule id: sshd\_disable\_empty\_passwords
### Title: Disable SSH Access via Empty Passwords
### Description:

```
To explicitly disallow SSH login from accounts with
empty passwords, add or correct the following line in /etc/ssh/sshd_config:

PermitEmptyPasswords no

Any accounts with empty passwords should be disabled immediately, and PAM configuration
should prevent users from being able to assign themselves empty passwords.
```

## Rule id: sshd\_do\_not\_permit\_user\_env
### Title: Do Not Allow SSH Environment Options
### Description:

```
To ensure users are not able to override environment
variables of the SSH daemon, add or correct the following line
in /etc/ssh/sshd_config:
PermitUserEnvironment no
```

## Rule id: sshd\_use\_approved\_ciphers
### Title: Use Only Approved Ciphers
### Description:

```
Limit the ciphers to those algorithms which are approved.
Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode.
The following line in /etc/ssh/sshd_config
demonstrates use of approved ciphers:
Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc
The man page sshd_config(5) contains a list of supported ciphers.

The rule is parametrized to use the following ciphers: .
```

## Rule id: sshd\_use\_approved\_macs
### Title: Use Only Approved MACs
### Description:

```
Limit the MACs to those hash algorithms which are approved.
The following line in /etc/ssh/sshd_config
demonstrates use of approved MACs:

MACs hmac-sha2-512,hmac-sha2-256,hmac-sha1

The man page sshd_config(5) contains a list of supported MACs.

The rule is parametrized to use the following MACs: .
```

## Rule id: sshd\_use\_approved\_kexs
### Title: Use Only Approved KEXs
### Description:

```
Limit the KEXs to those key exchange algorithms which are approved.
The following line in /etc/ssh/sshd_config
demonstrates use of approved KEXs:
KexAlgorithms 

The man page sshd_config(5) contains a list of supported MACs.
The rule is parametrized to use the following KEXs: .
```

## Rule id: sshd\_set\_keepalive
### Title: Set SSH Client Alive Count Max
### Description:

```
The SSH server sends at most ClientAliveCountMax messages
during a SSH session and waits for a response from the SSH client.
The option ClientAliveInterval configures timeout after
each ClientAliveCountMax message. If the SSH server does not
receive a response from the client, then the connection is considered idle
and terminated.
For SSH earlier than v8.2, a ClientAliveCountMax value of 0
causes an idle timeout precisely when the ClientAliveInterval is set.
Starting with v8.2, a value of 0 disables the timeout functionality
completely. If the option is set to a number greater than 0, then
the idle session will be disconnected after
ClientAliveInterval * ClientAliveCountMax seconds.
```

## Rule id: sshd\_set\_idle\_timeout
### Title: Set SSH Idle Timeout Interval
### Description:

```
SSH allows administrators to set an idle timeout interval. After this interval
has passed, the idle user will be automatically logged out.

To set an idle timeout interval, edit the following line in /etc/ssh/sshd_config as
follows:
ClientAliveInterval 

The timeout interval is given in seconds. For example, have a timeout
of 10 minutes, set interval to 600.

If a shorter timeout has already been set for the login shell, that value will
preempt any SSH setting made in /etc/ssh/sshd_config. Keep in mind that
some processes may stop SSH  from correctly detecting that the user is idle.
```

## Rule id: sshd\_set\_login\_grace\_time
### Title: Set SSH LoginGraceTime limit
### Description:

```
The LoginGraceTime parameter specifies the time allowed for successful authentication to
the SSH server. The longer the Grace period is the more open unauthenticated connections
can exist. Like other session controls in this session the Grace Period should be limited to
appropriate organizational limits to ensure the service is available for needed access.

To set LoginGraceTime edit /etc/ssh/sshd_config as follows:
LoginGraceTime 

Note: Local site policy may be more restrictive.
```

## Rule id: sshd\_configure\_allow\_users
### Title: Restrict sshd user access via AllowUsers
### Description:

```
AllowUsers gives the system administrator the option of allowing specific users to
ssh into the system.

- The list consists of space separated user names
- Numeric user IDs are not recognized with this variable
- A system administrator may restrict user access further by only allowing the
  allowed users to log in from a particular host by specifying the entry as
  user@host.
```

## Rule id: sshd\_configure\_deny\_users
### Title: Restrict sshd user access via DenyUsers
### Description:

```
DenyUsers gives the system administrator the option of denying specific users to
ssh into the system.

- The list consists of space separated user names
- Numeric user IDs are not recognized with this variable
- A system administrator may restrict user access further by only allowing the
  allowed users to log in from a particular host by specifying the entry as
  user@host.
```

## Rule id: sshd\_configure\_allow\_groups
### Title: Restrict sshd user access via AllowGroups
### Description:

```
AllowGroups gives the system administrator the option of allowing specific groups to
ssh into the system.

- The list consists of space separated group names
- Numeric group IDs are not recognized with this variable
```

## Rule id: sshd\_configure\_deny\_groups
### Title: Restrict sshd user access via DenyGroups
### Description:

```
DenyGroups gives the system administrator the option of denying specific groups to
ssh into the system.

- The list consists of space separated group names.
- Numeric group IDs are not recognized with this variable.
```

## Rule id: sshd\_enable\_warning\_banner\_net
### Title: Enable SSH Warning Banner
### Description:

```
To enable the warning banner and ensure it is consistent
across the system, add or correct the following line in /etc/ssh/sshd_config:
Banner /etc/issue.net
Another section contains information on how to create an
appropriate system-wide warning banner.
```

## Rule id: sshd\_enable\_pam
### Title: Enable PAM
### Description:

```
UsePAM Enables the Pluggable Authentication Module interface. If set to “yes” this will
enable PAM authentication using ChallengeResponseAuthentication and
PasswordAuthentication in addition to PAM account and session module processing for all
authentication types.

To enable PAM authentication, add or correct the following line in the
/etc/ssh/sshd_config file:
UsePAM yes
```

## Rule id: sshd\_set\_maxstartups
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

## Rule id: sshd\_set\_max\_sessions
### Title: Set SSH MaxSessions limit
### Description:

```
The MaxSessions parameter specifies the maximum number of open sessions permitted
from a given connection. To set MaxSessions edit
/etc/ssh/sshd_config as follows: MaxSessions 
```

## Rule id: package\_pam\_pwquality\_installed
### Title: Install pam\_pwquality Package
### Description:

```
The libpam-pwquality package can be installed with the following command:

$ apt-get install libpam-pwquality
```

## Rule id: accounts\_password\_pam\_minlen
### Title: Ensure PAM Enforces Password Requirements - Minimum Length
### Description:

```
The pam_pwquality module's minlen parameter controls requirements for
minimum characters required in a password. Add minlen=
after pam_pwquality to set minimum password length requirements.
```

## Rule id: accounts\_password\_pam\_minclass
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

## Rule id: accounts\_password\_pam\_dcredit
### Title: Ensure PAM Enforces Password Requirements - Minimum Digit Characters
### Description:

```
The pam_pwquality module's dcredit parameter controls requirements for
usage of digits in a password. When set to a negative number, any password will be required to
contain that many digits. When set to a positive number, pam_pwquality will grant +1 additional
length credit for each digit. Modify the dcredit setting in
/etc/security/pwquality.conf to require the use of a digit in passwords.
```

## Rule id: accounts\_password\_pam\_ucredit
### Title: Ensure PAM Enforces Password Requirements - Minimum Uppercase Characters
### Description:

```
The pam_pwquality module's ucredit= parameter controls requirements for
usage of uppercase letters in a password. When set to a negative number, any password will be required to
contain that many uppercase characters. When set to a positive number, pam_pwquality will grant +1 additional
length credit for each uppercase character. Modify the ucredit setting in
/etc/security/pwquality.conf to require the use of an uppercase character in passwords.
```

## Rule id: accounts\_password\_pam\_ocredit
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

## Rule id: accounts\_password\_pam\_lcredit
### Title: Ensure PAM Enforces Password Requirements - Minimum Lowercase Characters
### Description:

```
The pam_pwquality module's lcredit parameter controls requirements for
usage of lowercase letters in a password. When set to a negative number, any password will be required to
contain that many lowercase characters. When set to a positive number, pam_pwquality will grant +1 additional
length credit for each lowercase character. Modify the lcredit setting in
/etc/security/pwquality.conf to require the use of a lowercase character in passwords.
```

## Rule id: accounts\_password\_pam\_retry
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

## Rule id: accounts\_passwords\_pam\_tally2
### Title: Set Deny For Failed Password Attempts
### Description:

```
The Ubuntu 20.04 operating system must lock an account after - at most - 
consecutive invalid access attempts.
```

## Rule id: accounts\_password\_pam\_pwhistory\_remember
### Title: Limit Password Reuse
### Description:

```
Do not allow users to reuse recent passwords. This can be
accomplished by using the remember option for the
pam_pwhistory PAM modules.

In the file /etc/pam.d/common-password, make sure the parameters

remember is present, and that the value

for the remember parameter is  or greater. For example:

password required pam_pwhistory.so 

The DoD STIG requirement is 5 passwords.
```

## Rule id: accounts\_password\_all\_shadowed\_sha512
### Title: Verify All Account Password Hashes are Shadowed with SHA512
### Description:

```
Verify the operating system requires the shadow password suite
configuration be set to encrypt interactive user passwords using a strong
cryptographic hash.
Check that the interactive user account passwords are using a strong
password hash with the following command:
# sudo cut -d: -f2 /etc/shadow
$6$kcOnRq/5$NUEYPuyL.wghQwWssXRcLRFiiru7f5JPV6GaJhNC2aK5F3PZpE/BCCtwrxRc/AInKMNX3CdMw11m9STiql12f/
Password hashes ! or * indicate inactive accounts not
available for logon and are not evaluated.
If any interactive user password hash does not begin with $6,
this is a finding.
```

## Rule id: accounts\_maximum\_age\_login\_defs
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

## Rule id: accounts\_password\_set\_max\_life\_existing
### Title: Set Existing Passwords Maximum Age
### Description:

```
Configure non-compliant accounts to enforce a 60-day maximum password lifetime
restriction by running the following command:
$ sudo chage -M 
```

## Rule id: accounts\_minimum\_age\_login\_defs
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

## Rule id: accounts\_password\_set\_min\_life\_existing
### Title: Set Existing Passwords Minimum Age
### Description:

```
Configure non-compliant accounts to enforce a 24 hours/1 day minimum password
lifetime by running the following command:
$ sudo chage -m 
```

## Rule id: accounts\_password\_warn\_age\_login\_defs
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

## Rule id: account\_disable\_post\_pw\_expiration
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

## Rule id: last\_change\_date\_in\_past
### Title: Ensure all users last password change date is in the past
### Description:

```
All users should have a password change date in the past.
```

## Rule id: no\_shelllogin\_for\_systemaccounts
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

## Rule id: accounts\_no\_gid\_except\_zero
### Title: Ensure default group for the root account is GID 0
### Description:

```
The usermod command can be used to specify which group the root user belongs
to. This affects permissions of files that are created by the root user.
Using GID 0 for the root account helps prevent root-owned files from
accidentally becoming accessible to non-privileged users.
```

## Rule id: accounts\_umask\_etc\_csh\_cshrc
### Title: Ensure the Default C Shell Umask is Set Correctly
### Description:

```
To ensure the default umask for users of the C shell is set properly,
add or correct the umask setting in /etc/csh.cshrc to read as follows:
umask 
```

## Rule id: accounts\_umask\_etc\_login\_defs
### Title: Ensure the Default Umask is Set Correctly in login.defs
### Description:

```
To ensure the default umask controlled by /etc/login.defs is set properly,
add or correct the UMASK setting in /etc/login.defs to read as follows:
UMASK 
```

## Rule id: accounts\_umask\_etc\_profile
### Title: Ensure the Default Umask is Set Correctly in /etc/profile
### Description:

```
To ensure the default umask controlled by /etc/profile is set properly,
add or correct the umask setting in /etc/profile to read as follows:
umask 
```

## Rule id: accounts\_umask\_etc\_bashrc
### Title: Ensure the Default Bash Umask is Set Correctly
### Description:

```
To ensure the default umask for users of the Bash shell is set properly,
add or correct the umask setting in /etc/bashrc to read
as follows:
umask 
```

## Rule id: accounts\_umask\_interactive\_users
### Title: Ensure the Default Umask is Set Correctly For Interactive Users
### Description:

```
Remove the UMASK environment variable from all interactive users initialization files.
```

## Rule id: accounts\_tmout
### Title: Set Interactive Session Timeout
### Description:

```
Setting the TMOUT option in /etc/profile ensures that
all user sessions will terminate based on inactivity. The TMOUT

setting in a file loaded by /etc/profile, e.g.
/etc/profile.d/tmout.sh should read as follows:
TMOUT=
```

## Rule id: use\_pam\_wheel\_group\_for\_su
### Title: Enforce usage of pam\_wheel with group parameter for su authentication
### Description:

```
To ensure that only users who are members of the group set in the group
pam_wheel parameter can run commands with altered privileges through the su
command, make sure that the following line exists in the file /etc/pam.d/su:
  auth             required        pam_wheel.so use_uid group=
```

## Rule id: ensure\_pam\_wheel\_group\_empty
### Title: Ensure the group used by pam\_wheel module exists on system and is empty
### Description:

```
Ensure that the group  referenced by the pam_wheel
group parameter exists and has no members. This ensures that no user can run commands with
altered privileges through the su command.
```

## Rule id: file\_owner\_etc\_passwd
### Title: Verify User Who Owns passwd File
### Description:

```
 To properly set the owner of /etc/passwd, run the command: $ sudo chown root /etc/passwd 
```

## Rule id: file\_groupowner\_etc\_passwd
### Title: Verify Group Who Owns passwd File
### Description:

```
 To properly set the group owner of /etc/passwd, run the command: $ sudo chgrp root /etc/passwd
```

## Rule id: file\_permissions\_etc\_passwd
### Title: Verify Permissions on passwd File
### Description:

```
To properly set the permissions of /etc/passwd, run the command:
$ sudo chmod 0644 /etc/passwd
```

## Rule id: file\_owner\_backup\_etc\_gshadow
### Title: Verify User Who Owns Backup gshadow File
### Description:

```
 To properly set the owner of /etc/gshadow-, run the command: $ sudo chown root /etc/gshadow- 
```

## Rule id: file\_groupowner\_backup\_etc\_gshadow
### Title: Verify Group Who Owns Backup gshadow File
### Description:

```
 To properly set the group owner of /etc/gshadow-, run the command: $ sudo chgrp shadow /etc/gshadow-
```

## Rule id: file\_permissions\_backup\_etc\_gshadow
### Title: Verify Permissions on Backup gshadow File
### Description:

```
To properly set the permissions of /etc/gshadow-, run the command:
$ sudo chmod 0640 /etc/gshadow-
```

## Rule id: file\_owner\_etc\_shadow
### Title: Verify User Who Owns shadow File
### Description:

```
 To properly set the owner of /etc/shadow, run the command: $ sudo chown root /etc/shadow 
```

## Rule id: file\_groupowner\_etc\_shadow
### Title: Verify Group Who Owns shadow File
### Description:

```
 To properly set the group owner of /etc/shadow, run the command: $ sudo chgrp shadow /etc/shadow
```

## Rule id: file\_permissions\_etc\_shadow
### Title: Verify Permissions on shadow File
### Description:

```
To properly set the permissions of /etc/shadow, run the command:
$ sudo chmod 0640 /etc/shadow
```

## Rule id: file\_owner\_etc\_group
### Title: Verify User Who Owns group File
### Description:

```
 To properly set the owner of /etc/group, run the command: $ sudo chown root /etc/group 
```

## Rule id: file\_groupowner\_etc\_group
### Title: Verify Group Who Owns group File
### Description:

```
 To properly set the group owner of /etc/group, run the command: $ sudo chgrp root /etc/group
```

## Rule id: file\_permissions\_etc\_group
### Title: Verify Permissions on group File
### Description:

```
To properly set the permissions of /etc/passwd, run the command:
$ sudo chmod 0644 /etc/passwd
```

## Rule id: file\_owner\_backup\_etc\_passwd
### Title: Verify User Who Owns Backup passwd File
### Description:

```
 To properly set the owner of /etc/passwd-, run the command: $ sudo chown root /etc/passwd- 
```

## Rule id: file\_groupowner\_backup\_etc\_passwd
### Title: Verify Group Who Owns Backup passwd File
### Description:

```
 To properly set the group owner of /etc/passwd-, run the command: $ sudo chgrp root /etc/passwd-
```

## Rule id: file\_permissions\_backup\_etc\_passwd
### Title: Verify Permissions on Backup passwd File
### Description:

```
To properly set the permissions of /etc/passwd-, run the command:
$ sudo chmod 0644 /etc/passwd-
```

## Rule id: file\_owner\_backup\_etc\_shadow
### Title: Verify Group Who Owns Backup shadow File
### Description:

```
 To properly set the owner of /etc/shadow-, run the command: $ sudo chown root /etc/shadow- 
```

## Rule id: file\_groupowner\_backup\_etc\_shadow
### Title: Verify User Who Owns Backup shadow File
### Description:

```
 To properly set the group owner of /etc/shadow-, run the command: $ sudo chgrp shadow /etc/shadow-
```

## Rule id: file\_permissions\_backup\_etc\_shadow
### Title: Verify Permissions on Backup shadow File
### Description:

```
To properly set the permissions of /etc/shadow-, run the command:
$ sudo chmod 0640 /etc/shadow-
```

## Rule id: file\_owner\_backup\_etc\_group
### Title: Verify User Who Owns Backup group File
### Description:

```
 To properly set the owner of /etc/group-, run the command: $ sudo chown root /etc/group- 
```

## Rule id: file\_groupowner\_backup\_etc\_group
### Title: Verify Group Who Owns Backup group File
### Description:

```
 To properly set the group owner of /etc/group-, run the command: $ sudo chgrp root /etc/group-
```

## Rule id: file\_permissions\_backup\_etc\_group
### Title: Verify Permissions on Backup group File
### Description:

```
To properly set the permissions of /etc/group-, run the command:
$ sudo chmod 0644 /etc/group-
```

## Rule id: file\_owner\_etc\_gshadow
### Title: Verify User Who Owns gshadow File
### Description:

```
 To properly set the owner of /etc/gshadow, run the command: $ sudo chown root /etc/gshadow 
```

## Rule id: file\_groupowner\_etc\_gshadow
### Title: Verify Group Who Owns gshadow File
### Description:

```
 To properly set the group owner of /etc/gshadow, run the command: $ sudo chgrp shadow /etc/gshadow
```

## Rule id: file\_permissions\_etc\_gshadow
### Title: Verify Permissions on gshadow File
### Description:

```
To properly set the permissions of /etc/gshadow, run the command:
$ sudo chmod 0640 /etc/gshadow
```

## Rule id: file\_permissions\_unauthorized\_world\_writable
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

## Rule id: no\_files\_unowned\_by\_user
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

## Rule id: no\_ungrouped\_files\_or\_dirs
### Title: Ensure no ungrouped files or directories exist
### Description:

```
Sometimes when administrators delete users or groups from the system they
neglect to remove all files owned by those users or groups. A new user who
is assigned the deleted user's user ID or group ID may then end up "owning"
these files, and thus have more access on the system than was intended.
```

## Rule id: no\_empty\_password\_field
### Title: Lock Accounts With Empty Password Field
### Description:

```
If an account is configured for password authentication
but does not have an assigned password, it may be possible to log
into the account without authentication. Lock all accounts with empty
password field on /etc/shadow to prevent logins with empty
passwords.
```

## Rule id: accounts\_no\_uid\_except\_zero
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

## Rule id: accounts\_root\_path\_dirs\_no\_write
### Title: Ensure that Root's Path Does Not Include World or Group-Writable Directories
### Description:

```
For each element in root's path, run:
# ls -ld 
and ensure that write permissions are disabled for group and
other.
```

## Rule id: accounts\_user\_interactive\_home\_directory\_exists
### Title: All Interactive Users Home Directories Must Exist
### Description:

```
Create home directories to all interactive users that currently do not
have a home directory assigned. Use the following commands to create the user
home directory assigned in /etc/passwd:
$ sudo mkdir /home/
```

## Rule id: file\_permissions\_home\_directories
### Title: All Interactive User Home Directories Must Have mode 0750 Or Less Permissive
### Description:

```
Change the mode of interactive users home directories to 0750. To
change the mode of interactive users home directory, use the
following command:
$ sudo chmod 0750 /home/
```

## Rule id: adduser\_home\_directories\_mode
### Title: Ensure appropriate umask set for adduser
### Description:

```
While the system administrator can establish secure permissions for users' home
directories, the users can easily override these.

Setting DIRMODE=0750 for adduser helps ensure safe
default permissions are chosen.
```

## Rule id: useradd\_home\_directories\_mode
### Title: Ensure appropriate homedir mode set for useradd
### Description:

```
While the system administrator can establish secure permissions for users' home
directories, the users can easily override these.

Setting HOME_MODE=750 on /etc/login.defs for useradd helps
ensure safe default permissions are chosen.
```

## Rule id: accounts\_users\_own\_home\_directories
### Title: Ensure users own their home directories
### Description:

```
The user home directory is space defined for the particular user to set local
environment variables and to store personal files. Since the user is
accountable for files stored in the user home directory, the user must be
the owner of the directory.
```

## Rule id: accounts\_user\_dot\_user\_ownership
### Title: User Initialization Files Must Be Owned By the Primary User
### Description:

```
Set the owner of the user initialization files for interactive users to
the primary owner with the following command:
$ sudo chown 
```

## Rule id: no\_group\_world\_writable\_dot\_files
### Title: Ensure users' dot files are not group or world writable
### Description:

```
While the system administrator can establish secure permissions for users'
"dot" files, the users can easily override these. Group or world-writable
user configuration files may enable malicious users to steal or modify
other users' data or to gain another user's system privileges.
```

## Rule id: no\_forward\_files
### Title: Ensure no users have .forward files
### Description:

```
The .forward file specifies an email address to forward the user's mail to. Use
of the .forward file poses a security risk in that sensitive data may be
inadvertently transferred outside the organization. The .forward file also
poses a risk as it can be used to execute commands that may perform
unintended actions.
```

## Rule id: no\_netrc\_files
### Title: Verify No netrc Files Exist
### Description:

```
The .netrc files contain login information
used to auto-login into FTP servers and reside in the user's home
directory. These files may contain unencrypted passwords to
remote FTP servers making them susceptible to access by unauthorized
users and should not be used.  Any .netrc files should be removed.
```

## Rule id: no\_group\_world\_readable\_netrc\_files
### Title: Ensure users' .netrc Files are not group or world accessible
### Description:

```
While the system administrator can establish secure permissions for users'
.netrc files, the users can easily override these. files may contain
unencrypted passwords that may be used to attack other systems.
```

## Rule id: no\_rsh\_trust\_files
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

## Rule id: all\_etc\_passwd\_groups\_exist\_in\_etc\_group
### Title: Ensure all groups in /etc/passwd exist in /etc/group
### Description:

```
Over time, system administration errors and changes can lead to groups being
defined in /etc/passwd but not in /etc/group . Groups defined in the
/etc/passwd file but not in the /etc/group file pose a threat to system
security since group permissions are not properly managed.
```

## Rule id: no\_duplicate\_uids
### Title: Ensure no duplicate UIDs exist
### Description:

```
Although the useradd program will not let you create a duplicate User ID (UID),
it is possible for an administrator to manually edit the /etc/passwd file
and change the UID field. Users must be assigned unique UIDs for
accountability and to ensure appropriate access protections.
```

## Rule id: no\_duplicate\_gids
### Title: Ensure no duplicate GIDs exist
### Description:

```
Although the groupadd program will not let you create a duplicate Group ID
(GID), it is possible for an administrator to manually edit the /etc/group
file and change the GID field. User groups must be assigned unique GIDs for
accountability and to ensure appropriate access protections.
```

## Rule id: no\_duplicate\_user\_names
### Title: Ensure no duplicate user names exist
### Description:

```
Although the useradd program will not let you create a duplicate user name, it
is possible for an administrator to manually edit the /etc/passwd file and
change the user name. If a user is assigned a duplicate user name, it will
create and have access to files with the first UID for that username in
/etc/passwd . For example, if "test4" has a UID of 1000 and a subsequent
"test4" entry has a UID of 2000, logging in as "test4" will use UID 1000.
Effectively, the UID is shared, which is a security problem.
```

## Rule id: no\_duplicate\_group\_names
### Title: Ensure no duplicate group names exist
### Description:

```
Although the groupadd program will not let you create a duplicate group name,
it is possible for an administrator to manually edit the /etc/group file
and change the group name. If a group is assigned a duplicate group name,
it will create and have access to files with the first GID for that group
in /etc/group . Effectively, the GID is shared, which is a security
problem.
```

## Rule id: ensure\_shadow\_group\_empty
### Title: Ensure shadow group is empty
### Description:

```
The shadow group allows system programs which require access the ability to
read the /etc/shadow file. No users should be assigned to the shadow group.
Any users assigned to the shadow group would be granted read access to the
/etc/shadow file. If attackers can gain read access to the /etc/shadow
file, they can easily run a password cracking program against the hashed
passwords to break them. Other security information that is stored in the
/etc/shadow file (such as expiration) could also be useful to subvert
additional user accounts.
```

## Rule id: partition\_for\_var
### Title: Ensure /var Located On Separate Partition
### Description:

```
The /var directory is used by daemons and other system
services to store frequently-changing data. Ensure that /var has its own partition
or logical volume at installation time, or migrate it using LVM.
```

## Rule id: partition\_for\_var\_tmp
### Title: Ensure /var/tmp Located On Separate Partition
### Description:

```
The /var/tmp directory is a world-writable directory used
for temporary file storage. Ensure it has its own partition or
logical volume at installation time, or migrate it using LVM.
```

## Rule id: partition\_for\_var\_log
### Title: Ensure /var/log Located On Separate Partition
### Description:

```
System logs are stored in the /var/log directory.

Ensure that /var/log has its own partition or logical
volume at installation time, or migrate it using LVM.
```

## Rule id: partition\_for\_var\_log\_audit
### Title: Ensure /var/log/audit Located On Separate Partition
### Description:

```
Audit logs are stored in the /var/log/audit directory.

Ensure that /var/log/audit has its own partition or logical
volume at installation time, or migrate it using LVM.
Make absolutely certain that it is large enough to store all
audit logs that will be created by the auditing daemon.
```

## Rule id: partition\_for\_home
### Title: Ensure /home Located On Separate Partition
### Description:

```
If user home directories will be stored locally, create a separate partition
for /home at installation time (or migrate it later using LVM). If
/home will be mounted from another system such as an NFS server, then
creating a separate partition is not necessary at installation time, and the
mountpoint can instead be configured later.
```

## Rule id: ensure\_apparmor\_enforce
### Title: Ensure all AppArmor Profiles are in enforce mode
### Description:

```
AppArmor profiles define what resources applications are able to access.
```

## Rule id: kernel\_module\_dccp\_disabled
### Title: Disable DCCP Support
### Description:

```
The Datagram Congestion Control Protocol (DCCP) is a
relatively new transport layer protocol, designed to support
streaming media and telephony.

To configure the system to prevent the dccp
kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:
install dccp /bin/true
```

## Rule id: kernel\_module\_sctp\_disabled
### Title: Disable SCTP Support
### Description:

```
The Stream Control Transmission Protocol (SCTP) is a
transport layer protocol, designed to support the idea of
message-oriented communication, with several streams of messages
within one connection.

To configure the system to prevent the sctp
kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:
install sctp /bin/true
```

## Rule id: kernel\_module\_rds\_disabled
### Title: Disable RDS Support
### Description:

```
The Reliable Datagram Sockets (RDS) protocol is a transport
layer protocol designed to provide reliable high-bandwidth,
low-latency communications between nodes in a cluster.

To configure the system to prevent the rds
kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:
install rds /bin/true
```

## Rule id: kernel\_module\_tipc\_disabled
### Title: Disable TIPC Support
### Description:

```
The Transparent Inter-Process Communication (TIPC) protocol
is designed to provide communications between nodes in a
cluster.

To configure the system to prevent the tipc
kernel module from being loaded, add the following line to a file in the directory /etc/modprobe.d:
install tipc /bin/true
```

## Rule id: package\_audit\_installed
### Title: Ensure the audit Subsystem is Installed
### Description:

```
The audit package should be installed.
```

## Rule id: service\_auditd\_enabled
### Title: Enable auditd Service
### Description:

```
The auditd service is an essential userspace component of
the Linux Auditing System, as it is responsible for writing audit records to
disk.

The auditd service can be enabled with the following command:
$ sudo systemctl enable auditd.service
```

## Rule id: grub2\_audit\_argument
### Title: Enable Auditing for Processes Which Start Prior to the Audit Daemon
### Description:

```
To ensure all processes can be audited, even those which start
prior to the audit daemon, add the argument audit=1 to the default
GRUB 2 command line for the Linux operating system in

/etc/default/grub, so that the line looks similar to
GRUB_CMDLINE_LINUX="... audit=1 ..."
In case the GRUB_DISABLE_RECOVERY is set to true, then the parameter should be added to the GRUB_CMDLINE_LINUX_DEFAULT instead.
```

## Rule id: zipl\_audit\_argument
### Title: Enable Auditing to Start Prior to the Audit Daemon in zIPL
### Description:

```
To ensure all processes can be audited, even those which start prior to the audit daemon,
check that all boot entries in /boot/loader/entries/*.conf have audit=1
included in its options.

To ensure that new kernels and boot entries continue to enable audit,
add audit=1 to /etc/kernel/cmdline.
```

## Rule id: grub2\_audit\_backlog\_limit\_argument
### Title: Extend Audit Backlog Limit for the Audit Daemon
### Description:

```
To improve the kernel capacity to queue all log events, even those which occurred
prior to the audit daemon, add the argument audit_backlog_limit=8192 to the default
GRUB 2 command line for the Linux operating system in
/etc/default/grub, in the manner below:
GRUB_CMDLINE_LINUX="crashkernel=auto rd.lvm.lv=VolGroup/LogVol06 rd.lvm.lv=VolGroup/lv_swap rhgb quiet rd.shell=0 audit=1 audit_backlog_limit=8192"
```

## Rule id: zipl\_audit\_backlog\_limit\_argument
### Title: Extend Audit Backlog Limit for the Audit Daemon in zIPL
### Description:

```
To improve the kernel capacity to queue all log events, even those which start prior to the audit daemon,
check that all boot entries in /boot/loader/entries/*.conf have audit_backlog_limit=8192
included in its options.
To ensure that new kernels and boot entries continue to extend the audit log events queue,
add audit_backlog_limit=8192 to /etc/kernel/cmdline.
```

## Rule id: auditd\_data\_retention\_max\_log\_file
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

## Rule id: auditd\_data\_retention\_max\_log\_file\_action
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

## Rule id: auditd\_data\_retention\_space\_left\_action
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

## Rule id: auditd\_data\_retention\_action\_mail\_acct
### Title: Configure auditd mail\_acct Action on Low Disk Space
### Description:

```
The auditd service can be configured to send email to
a designated account in certain situations. Add or correct the following line
in /etc/audit/auditd.conf to ensure that administrators are notified
via email for those situations:
action_mail_acct = 
```

## Rule id: auditd\_data\_retention\_admin\_space\_left\_action
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

## Rule id: audit\_rules\_time\_clock\_settime
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

## Rule id: audit\_rules\_time\_settimeofday
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

## Rule id: audit\_rules\_time\_adjtimex
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

## Rule id: audit\_rules\_time\_stime
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

## Rule id: audit\_rules\_time\_watch\_localtime
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

## Rule id: audit\_rules\_usergroup\_modification\_group
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

## Rule id: audit\_rules\_usergroup\_modification\_passwd
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

## Rule id: audit\_rules\_usergroup\_modification\_gshadow
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

## Rule id: audit\_rules\_usergroup\_modification\_shadow
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

## Rule id: audit\_rules\_usergroup\_modification\_opasswd
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

## Rule id: audit\_rules\_networkconfig\_modification
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
-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file, setting ARCH to either b32 or b64 as
appropriate for your system:
-a always,exit -F arch=ARCH -S sethostname,setdomainname -F key=audit_rules_networkconfig_modification
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification
```

## Rule id: audit\_rules\_mac\_modification
### Title: Record Events that Modify the System's Mandatory Access Controls
### Description:

```
If the auditd daemon is configured to use the
augenrules program to read audit rules during daemon startup (the
default), add the following line to a file with suffix .rules in the
directory /etc/audit/rules.d:
-w /etc/selinux/ -p wa -k MAC-policy
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-w /etc/selinux/ -p wa -k MAC-policy
```

## Rule id: audit\_rules\_login\_events\_faillog
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

## Rule id: audit\_rules\_login\_events\_lastlog
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

## Rule id: audit\_rules\_login\_events\_tallylog
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

## Rule id: audit\_rules\_session\_events
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

## Rule id: audit\_rules\_dac\_modification\_chmod
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

## Rule id: audit\_rules\_dac\_modification\_chown
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

## Rule id: audit\_rules\_dac\_modification\_fchmod
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

## Rule id: audit\_rules\_dac\_modification\_fchmodat
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

## Rule id: audit\_rules\_dac\_modification\_fchown
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

## Rule id: audit\_rules\_dac\_modification\_fchownat
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

## Rule id: audit\_rules\_dac\_modification\_fremovexattr
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

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: audit\_rules\_dac\_modification\_fsetxattr
### Title: Record Events that Modify the System's Discretionary Access Controls - fsetxattr
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: audit\_rules\_dac\_modification\_lchown
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

## Rule id: audit\_rules\_dac\_modification\_lremovexattr
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

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: audit\_rules\_dac\_modification\_lsetxattr
### Title: Record Events that Modify the System's Discretionary Access Controls - lsetxattr
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: audit\_rules\_dac\_modification\_removexattr
### Title: Record Events that Modify the System's Discretionary Access Controls - removexattr
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root.

If the auditd daemon is configured to use the augenrules
program to read audit rules during daemon startup (the default), add the
following line to a file with suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod

If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod

If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: audit\_rules\_dac\_modification\_setxattr
### Title: Record Events that Modify the System's Discretionary Access Controls - setxattr
### Description:

```
At a minimum, the audit system should collect file permission
changes for all users and root. If the auditd daemon is configured
to use the augenrules program to read audit rules during daemon
startup (the default), add the following line to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following line to
/etc/audit/audit.rules file:
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
If the system is 64 bit then also add the following line:
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
```

## Rule id: audit\_rules\_unsuccessful\_file\_modification\_creat
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

## Rule id: audit\_rules\_unsuccessful\_file\_modification\_open
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

## Rule id: audit\_rules\_unsuccessful\_file\_modification\_openat
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

## Rule id: audit\_rules\_unsuccessful\_file\_modification\_truncate
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

## Rule id: audit\_rules\_unsuccessful\_file\_modification\_ftruncate
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

-a always,exit -F arch=b64 -S ftruncate -F exiu=-EACCES -F auid>=1000 -F auid!=unset -F key=access
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

## Rule id: audit\_rules\_privileged\_commands\_at
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - at
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/at -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/at -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_chage
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - chage
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chage -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/chage -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_chfn
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

## Rule id: audit\_rules\_privileged\_commands\_chsh
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - chsh
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chsh -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/chsh -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_crontab
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - crontab
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/crontab -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/crontab -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_gpasswd
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - gpasswd
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/gpasswd -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/gpasswd -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_mount
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - mount
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/mount -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/mount -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_newgidmap
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - newgidmap
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/newgidmap -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/newgidmap -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_newgrp
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - newgrp
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_newuidmap
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - newuidmap
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/newuidmap -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/newuidmap -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_postdrop
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - postdrop
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/postdrop -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/postdrop -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_postqueue
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - postqueue
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/postqueue -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/postqueue -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_ssh\_agent
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

## Rule id: audit\_rules\_privileged\_commands\_ssh\_keysign
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - ssh-keysign
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_su
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

## Rule id: audit\_rules\_privileged\_commands\_sudo
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - sudo
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/sudo -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/sudo -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_sudoedit
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - sudoedit
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/sudoedit -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/sudoedit -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_umount
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - umount
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/umount -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/umount -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_unix\_chkpwd
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - unix\_chkpwd
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/unix_chkpwd -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/unix_chkpwd -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_media\_export
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

## Rule id: audit\_rules\_file\_deletion\_events\_rename
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

## Rule id: audit\_rules\_file\_deletion\_events\_renameat
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

## Rule id: audit\_rules\_file\_deletion\_events\_unlink
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

## Rule id: audit\_rules\_file\_deletion\_events\_unlinkat
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

## Rule id: audit\_rules\_sysadmin\_actions
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

## Rule id: audit\_rules\_suid\_privilege\_function
### Title: Record Events When Privileged Executables Are Run
### Description:

```
Verify the system generates an audit record when privileged functions are executed.
# grep -iw execve 

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid

If both the "b32" and "b64" audit rules for "SUID" files are not defined, this is a finding.
If both the "b32" and "b64" audit rules for "SGID" files are not defined, this is a finding.
```

## Rule id: audit\_rules\_kernel\_module\_loading\_init
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

## Rule id: audit\_rules\_kernel\_module\_loading\_delete
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

## Rule id: audit\_rules\_privileged\_commands\_modprobe
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

## Rule id: audit\_rules\_privileged\_commands\_insmod
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

## Rule id: audit\_rules\_privileged\_commands\_rmmod
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

## Rule id: audit\_rules\_immutable
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

## Rule id: sshd\_disable\_x11\_forwarding
### Title: Disable X11 Forwarding
### Description:

```
The X11Forwarding parameter provides the ability to tunnel X11 traffic
through the connection to enable remote graphic connections.
SSH has the capability to encrypt remote X11 connections when SSH's
X11Forwarding option is enabled.

To disable X11 Forwarding, add or correct the
following line in /etc/ssh/sshd_config:
X11Forwarding no
```

## Rule id: sshd\_disable\_tcp\_forwarding
### Title: Disable SSH TCP Forwarding
### Description:

```
The AllowTcpForwarding parameter specifies whether TCP forwarding is permitted.
To disable TCP forwarding, add or correct the
following line in /etc/ssh/sshd_config:
AllowTcpForwarding no
```

## Rule id: account\_temp\_expire\_date
### Title: Assign Expiration Date to Temporary Accounts
### Description:

```
Temporary accounts are established as part of normal account activation
procedures when there is a need for short-term accounts. In the event
temporary or emergency accounts are required, configure the system to
terminate them after a documented time period. For every temporary and
emergency account, run the following command to set an expiration date on
it, substituting  and 
appropriately:
$ sudo chage -E 
 indicates the documented expiration date for the
account. For U.S. Government systems, the operating system must be
configured to automatically terminate these types of accounts after a
period of 72 hours.
```

## Rule id: dconf\_gnome\_screensaver\_lock\_enabled
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

## Rule id: vlock\_installed
### Title: Check that vlock is installed to allow session locking
### Description:

```
The Ubuntu 20.04 operating system must have vlock installed to allow for session locking.


The vlock package can be installed with the following command:

$ apt-get install vlock
```

## Rule id: verify\_use\_mappers
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

## Rule id: grub2\_uefi\_password
### Title: Set the UEFI Boot Loader Password
### Description:

```
The grub2 boot loader should have a superuser account and password
protection enabled to protect boot-time settings.

Since plaintext passwords are a security risk, generate a hash for the password
by running the following command:

$ grub2-mkpasswd-pbkdf2

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

## Rule id: ensure\_sudo\_group\_restricted
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

## Rule id: sudo\_require\_authentication
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

## Rule id: sshd\_enable\_pubkey\_auth
### Title: Enable PubkeyAuthentication
### Description:

```
Verify the sshd daemon allows public key authentication with the
following:
$ grep ^Pubkeyauthentication /etc/ssh/sshd_config
PubkeyAuthentication yes
```

## Rule id: smartcard\_pam\_enabled
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

## Rule id: banner\_etc\_issue\_net
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

## Rule id: package\_openssh-server\_installed
### Title: Install the OpenSSH Server Package
### Description:

```
The openssh-server package should be installed.
The openssh-server package can be installed with the following command:

$ apt-get install openssh-server
```

## Rule id: service\_sshd\_enabled
### Title: Enable the OpenSSH Service
### Description:

```
The SSH server service, sshd, is commonly needed.

The sshd service can be enabled with the following command:
$ sudo systemctl enable sshd.service
```

## Rule id: sshd\_use\_approved\_macs\_ordered\_stig
### Title: Use Only FIPS 140-2 Validated MACs
### Description:

```
Limit the MACs to those hash algorithms which are FIPS-approved.
The following line in /etc/ssh/sshd_config
demonstrates use of FIPS-approved MACs:
MACs hmac-sha2-512,hmac-sha2-256
This rule ensures that there are configured MACs mentioned
above (or their subset), keeping the given order of algorithms.
```

## Rule id: sshd\_use\_approved\_ciphers\_ordered\_stig
### Title: Use Only FIPS 140-2 Validated Ciphers
### Description:

```
Limit the ciphers to those algorithms which are FIPS-approved.
The following line in /etc/ssh/sshd_config
demonstrates use of FIPS-approved ciphers:
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
This rule ensures that there are configured ciphers mentioned
above (or their subset), keeping the given order of algorithms.
```

## Rule id: sshd\_x11\_use\_localhost
### Title: Prevent remote hosts from connecting to the proxy display
### Description:

```
The SSH daemon should prevent remote hosts from connecting to the proxy
display. Make sure that the option X11UseLocalhost is set to
yes within the SSH server configuration file.
```

## Rule id: accounts\_password\_pam\_difok
### Title: Ensure PAM Enforces Password Requirements - Minimum Different Characters
### Description:

```
The pam_pwquality module's difok parameter sets the number of characters
in a password that must not be present in and old password during a password change.

Modify the difok setting in /etc/security/pwquality.conf
to equal  to require differing characters
when changing passwords.
```

## Rule id: accounts\_password\_pam\_dictcheck
### Title: Ensure PAM Enforces Password Requirements - Prevent the Use of Dictionary Words
### Description:

```
The pam_pwquality module's dictcheck check if passwords contains dictionary words. When
dictcheck is set to 1 passwords will be checked for dictionary words.
```

## Rule id: package\_pam\_pwquality\_installed
### Title: Install pam\_pwquality Package
### Description:

```
The libpam-pwquality package can be installed with the following command:

$ apt-get install libpam-pwquality
```

## Rule id: accounts\_password\_pam\_enforcing
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

## Rule id: smartcard\_configure\_ca
### Title: Configure Smart Card Certificate Authority Validation
### Description:

```
Configure the operating system to do certificate status checking for PKI
authentication. Modify all of the cert_policy lines in
/etc/pam_pkcs11/pam_pkcs11.conf to include ca like so:
cert_policy = ca, ocsp_on, signature;
```

## Rule id: install\_smartcard\_packages
### Title: Install Smart Card Packages For Multifactor Authentication
### Description:

```
Configure the operating system to implement multifactor authentication by
installing the required package with the following command:

The libpam-pkcs11 package can be installed with the following command:

$ apt-get install libpam-pkcs11
```

## Rule id: package\_opensc\_installed
### Title: Install the opensc Package For Multifactor Authentication
### Description:

```
The opensc-pkcs11 package can be installed with the following command:

$ apt-get install opensc-pkcs11
```

## Rule id: smartcard\_configure\_cert\_checking
### Title: Configure Smart Card Certificate Status Checking
### Description:

```
Configure the operating system to do certificate status checking for PKI
authentication. Modify all of the cert_policy lines in
/etc/pam_pkcs11/pam_pkcs11.conf to include ocsp_on like so:
cert_policy = ca, ocsp_on, signature;
```

## Rule id: smartcard\_configure\_crl
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

## Rule id: accounts\_password\_pam\_unix\_remember
### Title: Limit Password Reuse
### Description:

```
Do not allow users to reuse recent passwords. This can be
accomplished by using the remember option for the pam_unix
or pam_pwhistory PAM modules.

In the file /etc/pam.d/system-auth, append remember=
to the line which refers to the pam_unix.so or pam_pwhistory.somodule, as shown below:

The DoD STIG requirement is 5 passwords.
```

## Rule id: accounts\_passwords\_pam\_faildelay\_delay
### Title: Enforce Delay After Failed Logon Attempts
### Description:

```
To configure the system to introduce a delay after failed logon attempts,
add or correct the pam_faildelay settings in
/etc/pam.d/common-auth to make sure its delay parameter
is at least  or greater. For example:
auth required pam_faildelay.so delay=
```

## Rule id: auditd\_data\_disk\_full\_action
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

## Rule id: file\_permissions\_var\_log\_audit
### Title: System Audit Logs Must Have Mode 0640 or Less Permissive
### Description:

```
If log_group in /etc/audit/auditd.conf is set to a group other than the root
group account, change the mode of the audit log files with the following command:
$ sudo chmod 0640 

Otherwise, change the mode of the audit log files with the following command:
$ sudo chmod 0600 
```

## Rule id: file\_ownership\_var\_log\_audit\_stig
### Title: System Audit Logs Must Be Owned By Root
### Description:

```
All audit logs must be owned by root user. By default, the path for audit log is /var/log/audit/.

To properly set the owner of /var/log/audit/*, run the command:
$ sudo chown root /var/log/audit/* 
```

## Rule id: file\_group\_ownership\_var\_log\_audit
### Title: System Audit Logs Must Be Group Owned By Root
### Description:

```
All audit logs must be group owned by root user. By default, the path for audit log is /var/log/audit/.

To properly set the group owner of /var/log/audit/*, run the command:
$ sudo chgrp root /var/log/audit/*
If log_group in /etc/audit/auditd.conf is set to a group other than the root
group account, change the group ownership of the audit logs to this specific group.
```

## Rule id: directory\_permissions\_var\_log\_audit
### Title: System Audit Logs Must Have Mode 0750 or Less Permissive
### Description:

```
If log_group in /etc/audit/auditd.conf is set to a group other than the root
group account, change the mode of the audit log files with the following command:
$ sudo chmod 0750 /var/log/audit

Otherwise, change the mode of the audit log files with the following command:
$ sudo chmod 0700 /var/log/audit
```

## Rule id: file\_permissions\_etc\_audit\_rulesd
### Title: Verify Permissions on /etc/audit/rules.d/\*.rules
### Description:

```
To properly set the permissions of /etc/audit/rules.d/*.rules, run the command:
$ sudo chmod 0640 /etc/audit/rules.d/*.rules
```

## Rule id: file\_permissions\_etc\_audit\_auditd
### Title: Verify Permissions on /etc/audit/auditd.conf and /etc/audit/audit.rules
### Description:

```
To properly set the permissions of /etc/audit/auditd.conf, run the command:
$ sudo chmod 0640 /etc/audit/auditd.conf

To properly set the permissions of /etc/audit/audit.rules, run the command:
$ sudo chmod 0640 /etc/audit/audit.rules
```

## Rule id: file\_ownership\_audit\_configuration
### Title: Audit Configuration Files Must Be Owned By Root
### Description:

```
All audit configuration files must be owned by root user.

To properly set the owner of /etc/audit/, run the command:
$ sudo chown root /etc/audit/ 

To properly set the owner of /etc/audit/rules.d/, run the command:
$ sudo chown root /etc/audit/rules.d/ 
```

## Rule id: file\_groupownership\_audit\_configuration
### Title: Audit Configuration Files Must Be Owned By Group root
### Description:

```
All audit configuration files must be owned by group root.
chown :root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*
```

## Rule id: audit\_rules\_unsuccessful\_file\_modification\_open\_by\_handle\_at
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

## Rule id: audit\_rules\_execution\_chcon
### Title: Record Any Attempts to Run chcon
### Description:

```
At a minimum, the audit system should collect any execution attempt
of the chcon command for all users and root. If the auditd
daemon is configured to use the augenrules program to read audit rules
during daemon startup (the default), add the following lines to a file with suffix
.rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add the following lines to
/etc/audit/audit.rules file:
-a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_apparmor\_parser
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

## Rule id: audit\_rules\_execution\_setfacl
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

## Rule id: audit\_rules\_execution\_chacl
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

## Rule id: audit\_rules\_privileged\_commands\_passwd
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - passwd
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/bin/passwd -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/bin/passwd -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_unix\_update
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - unix\_update
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_privileged\_commands\_usermod
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

## Rule id: audit\_rules\_privileged\_commands\_pam\_timestamp\_check
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - pam\_timestamp\_check
### Description:

```
At a minimum, the audit system should collect the execution of
privileged commands for all users and root. If the auditd daemon is
configured to use the augenrules program to read audit rules during
daemon startup (the default), add a line of the following form to a file with
suffix .rules in the directory /etc/audit/rules.d:
-a always,exit -F path=/usr/sbin/pam_timestamp_check
-F auid>=1000 -F auid!=unset -F key=privileged
If the auditd daemon is configured to use the auditctl
utility to read audit rules during daemon startup, add a line of the following
form to /etc/audit/audit.rules:
-a always,exit -F path=/usr/sbin/pam_timestamp_check
-F auid>=1000 -F auid!=unset -F key=privileged
```

## Rule id: audit\_rules\_kernel\_module\_loading\_finit
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

## Rule id: file\_permissions\_audit\_binaries
### Title: Verify that audit tools Have Mode 0755 or less
### Description:

```
The Ubuntu 20.04 operating system audit tools must have the proper
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

## Rule id: file\_ownership\_audit\_binaries
### Title: Verify that audit tools are owned by root
### Description:

```
The Ubuntu 20.04 operating system audit tools must have the proper
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

## Rule id: file\_groupownership\_audit\_binaries
### Title: Verify that audit tools are owned by group root
### Description:

```
The Ubuntu 20.04 operating system audit tools must have the proper
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

## Rule id: aide\_check\_audit\_tools
### Title: Configure AIDE to Verify the Audit Tools
### Description:

```
The Ubuntu 20.04 operating system file integrity tool must be
configured to protect the integrity of the audit tools.
```

## Rule id: auditd\_audispd\_configure\_sufficiently\_large\_partition
### Title: Configure a Sufficiently Large Partition for Audit Logs
### Description:

```
The Ubuntu 20.04 operating system must allocate audit record storage
capacity to store at least one weeks worth of audit records when audit
records are not immediately sent to a central audit record storage
facility.

The partition size needed to capture a week's worth of audit records is
based on the activity level of the system and the total storage capacity
available. In normal circumstances, 10.0 GB of storage space for audit
records will be sufficient.

Determine which partition the audit records are being written to with the
following command:

# grep log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Check the size of the partition that audit records are written to with the
following command:

# df -h /var/log/audit/
/dev/sda2 24G 10.4G 13.6G 43% /var/log/audit
```

## Rule id: package\_audit-audispd-plugins\_installed
### Title: Ensure the default plugins for the audit dispatcher are Installed
### Description:

```
The audit-audispd-plugins package should be installed.
```

## Rule id: auditd\_audispd\_configure\_remote\_server
### Title: Configure audispd Plugin To Send Logs To Remote Server
### Description:

```
Configure the audispd plugin to off-load audit records onto a different
system or media from the system being audited.

First, set the active option in
/etc/audisp/plugins.d/au-remote.conf

Set the remote_server option in /etc/audisp/audisp-remote.conf
with an IP address or hostname of the system that the audispd plugin should
send audit records to. For example
remote_server = 
```

## Rule id: auditd\_data\_retention\_space\_left
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

## Rule id: ensure\_rtc\_utc\_configuration
### Title: Ensure real-time clock is set to UTC
### Description:

```
Ensure that the system real-time clock (RTC) is set to Coordinated Universal Time (UTC).
```

## Rule id: audit\_sudo\_log\_events
### Title: Record Attempts to perform maintenance activities
### Description:

```
The Ubuntu 20.04 operating system must generate audit records for
privileged activities, nonlocal maintenance, diagnostic sessions and
other system-level access.

Verify the operating system audits activities performed during nonlocal
maintenance and diagnostic sessions. Run the following command:
$ sudo auditctl -l | grep sudo.log
-w /var/log/sudo.log -p wa -k maintenance
```

## Rule id: audit\_rules\_session\_events\_wtmp
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

## Rule id: audit\_rules\_session\_events\_utmp
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

## Rule id: audit\_rules\_session\_events\_btmp
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

## Rule id: audit\_rules\_privileged\_commands\_kmod\_0
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

## Rule id: audit\_rules\_privileged\_commands\_fdisk
### Title: Ensure auditd Collects Information on the Use of Privileged Commands - fdisk
### Description:

```
Configure the operating system to audit the execution of the partition
management program "fdisk".
```

## Rule id: auditd\_offload\_logs
### Title: Offload audit Logs to External Media
### Description:

```
The operating system must have a crontab script running weekly to
offload audit events of standalone systems.
```

## Rule id: accounts\_max\_concurrent\_login\_sessions
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

## Rule id: rsyslog\_remote\_access\_monitoring
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

## Rule id: set\_password\_hashing\_algorithm\_logindefs
### Title: Set Password Hashing Algorithm in /etc/login.defs
### Description:

```
In /etc/login.defs, add or correct the following line to ensure
the system will use SHA-512 as the hashing algorithm:
ENCRYPT_METHOD SHA512
```

## Rule id: package\_telnetd\_removed
### Title: Uninstall the telnet server
### Description:

```
The telnet daemon should be uninstalled.
```

## Rule id: package\_rsh-server\_removed
### Title: Uninstall rsh-server Package
### Description:

```
The rsh-server package can be removed with the following command:

$ apt-get remove rsh-server
```

## Rule id: ufw\_only\_required\_services
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

## Rule id: prevent\_direct\_root\_logins
### Title: Direct root Logins Are Not Allowed
### Description:

```
Configure the operating system to prevent direct logins to the
root account by performing the following operations:
$ sudo passwd -l root
```

## Rule id: service\_kdump\_disabled
### Title: Disable KDump Kernel Crash Analyzer (kdump)
### Description:

```
The kdump service provides a kernel crash dump analyzer. It uses the kexec
system call to boot a secondary kernel ("capture" kernel) following a system
crash, which can load information from the crashed kernel for analysis.

The kdump service can be disabled with the following command:
$ sudo systemctl mask --now kdump.service
```

## Rule id: encrypt\_partitions
### Title: Encrypt Partitions
### Description:

```
Ubuntu 20.04 natively supports partition encryption through the
Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to
encrypt a partition is during installation time.

For manual installations, select the Encrypt checkbox during
partition creation to encrypt the partition. When this
option is selected the system will prompt for a passphrase to use in
decrypting the partition. The passphrase will subsequently need to be entered manually
every time the system boots.


For automated/unattended installations, it is possible to use Kickstart by adding
the --encrypted and --passphrase= options to the definition of each partition to be
encrypted. For example, the following line would encrypt the root partition:
part / --fstype=ext4 --size=100 --onpart=hda1 --encrypted --passphrase=
Any PASSPHRASE is stored in the Kickstart in plaintext, and the Kickstart
must then be protected accordingly.
Omitting the --passphrase= option from the partition definition will cause the
installer to pause and interactively ask for the passphrase during installation.

By default, the Anaconda installer uses aes-xts-plain64 cipher
with a minimum 512 bit key size which should be compatible with FIPS enabled.


Detailed information on encrypting partitions using LUKS or LUKS ciphers can be found on
the Ubuntu 20.04 Documentation web site:

    
    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/encrypting-block-devices-using-luks_security-hardening.
```

## Rule id: package\_mfetp\_installed
### Title: Install Endpoint Security for Linux Threat Prevention
### Description:

```
The operating system must deploy Endpoint Security for Linux Threat
Prevention (ENSLTP).
```

## Rule id: permissions\_local\_var\_log
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

## Rule id: file\_groupowner\_var\_log
### Title: Verify Group Who Owns /var/log Directory
### Description:

```
 To properly set the group owner of /var/log, run the command: $ sudo chgrp syslog /var/log
```

## Rule id: file\_owner\_var\_log
### Title: Verify User Who Owns /var/log Directory
### Description:

```
 To properly set the owner of /var/log, run the command: $ sudo chown root /var/log 
```

## Rule id: file\_permissions\_var\_log
### Title: Verify Permissions on /var/log Directory
### Description:

```
To properly set the permissions of /var/log, run the command:
$ sudo chmod 0755 /var/log
```

## Rule id: file\_groupowner\_var\_log\_syslog
### Title: Verify Group Who Owns /var/log/syslog File
### Description:

```
 To properly set the group owner of /var/log/syslog, run the command: $ sudo chgrp adm /var/log/syslog
```

## Rule id: file\_owner\_var\_log\_syslog
### Title: Verify User Who Owns /var/log/syslog File
### Description:

```
 To properly set the owner of /var/log/syslog, run the command: $ sudo chown syslog /var/log/syslog 
```

## Rule id: file\_permissions\_var\_log\_syslog
### Title: Verify Permissions on /var/log/syslog File
### Description:

```
To properly set the permissions of /var/log/syslog, run the command:
$ sudo chmod 0640 /var/log/syslog
```

## Rule id: dir\_permissions\_binary\_dirs
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

## Rule id: dir\_ownership\_binary\_dirs
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

## Rule id: dir\_groupownership\_binary\_dirs
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

## Rule id: file\_permissions\_library\_dirs
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

## Rule id: dir\_permissions\_library\_dirs
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

## Rule id: file\_ownership\_library\_dirs
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

## Rule id: dir\_ownership\_library\_dirs
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

## Rule id: root\_permissions\_syslibrary\_files
### Title: Verify the system-wide library files in directories
"/lib", "/lib64", "/usr/lib/" and "/usr/lib64" are owned by root.
### Description:

```
System-wide library files are stored in the following directories
by default:
/lib
/lib64
/usr/lib
/usr/lib64

All system-wide shared library files should be protected from unauthorised
access. If any of these files is not owned by root, correct its owner with
the following command:
$ sudo chgrp root 
```

## Rule id: dir\_groupownership\_library\_dirs
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

## Rule id: chronyd\_or\_ntpd\_set\_maxpoll
### Title: Configure Time Service Maxpoll Interval
### Description:

```
The maxpoll should be configured to
 in /etc/ntp.conf or
/etc/chrony/chrony.conf to continuously poll time servers. To configure
maxpoll in /etc/ntp.conf or /etc/chrony/chrony.conf
add the following after each `server` entry:
maxpoll 
```

## Rule id: chronyd\_sync\_clock
### Title: Synchronize internal information system clocks
### Description:

```
Synchronizing internal information system clocks provides uniformity
of time stamps for information systems with multiple system clocks and
systems connected over a network.
```

## Rule id: apt\_conf\_disallow\_unauthenticated
### Title: Disable unauthenticated repositories in APT configuration
### Description:

```
Unauthenticated repositories should not be used for updates.
```

## Rule id: apparmor\_configured
### Title: Ensure AppArmor is Active and Configured
### Description:

```
Verify that the Apparmor tool is configured to
control whitelisted applications and user home directory access
control.

The apparmor service can be enabled with the following command:
$ sudo systemctl enable apparmor.service
```

## Rule id: policy\_temp\_passwords\_immediate\_change
### Title: Policy Requires Immediate Change of Temporary Passwords
### Description:

```
Temporary passwords for Ubuntu 20.04 operating system logons must
require an immediate change to a permanent password.

Verify that a policy exists that ensures when a user is created, it is
creating using a method that forces a user to change their password upon
their next login.
```

## Rule id: sssd\_offline\_cred\_expiration
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

## Rule id: is\_fips\_mode\_enabled
### Title: Verify '/proc/sys/crypto/fips\_enabled' exists
### Description:

```
On a system where FIPS 140-2 mode is enabled, /proc/sys/crypto/fips_enabled must exist.
To verify FIPS mode, run the following command:
cat /proc/sys/crypto/fips_enabled
```

## Rule id: only\_allow\_dod\_certs
### Title: Only Allow DoD PKI-established CAs
### Description:

```
The operating system must only allow the use of DoD PKI-established
certificate authorities for verification of the establishment of
protected sessions.
```

## Rule id: ufw\_rate\_limit
### Title: ufw Must rate-limit network interfaces
### Description:

```
The operating system must configure the uncomplicated firewall to
rate-limit impacted network interfaces.
```

## Rule id: clean\_components\_post\_updating
### Title: Ensure apt\_get Removes Previous Package Versions
### Description:

```
apt_get should be configured to remove previous software components after
new versions have been installed. To configure apt_get to remove the

previous software components after updating, set the ::Remove-Unused-Dependencies and
::Remove-Unused-Kernel-Packages


to true in .
```

## Rule id: display\_login\_attempts
### Title: Ensure PAM Displays Last Logon/Access Notification
### Description:

```
To configure the system to notify users of last logon/access
using pam_lastlog, add or correct the pam_lastlog
settings in
/etc/pam.d/login to read as follows:
session     required pam_lastlog.so showfailed
And make sure that the silent option is not set.
```

## Rule id: file\_permissions\_binary\_dirs
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

## Rule id: file\_ownership\_binary\_dirs
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

## Rule id: file\_groupownership\_system\_commands\_dirs
### Title: Verify that system commands files are group owned by root 
### Description:

```
System commands files are stored in the following directories by default:
/bin
/sbin
/usr/bin
/usr/sbin
/usr/local/bin
/usr/local/sbin

All files in these directories should be owned by the root group.
If the directory, or any file in these directories, is found to be owned
by a group other than root correct its ownership with the following command:
$ sudo chgrp root 
```

## Rule id: dconf\_gnome\_disable\_ctrlaltdel\_reboot
### Title: Disable Ctrl-Alt-Del Reboot Key Sequence in GNOME3
### Description:

```
By default, GNOME will reboot the system if the
Ctrl-Alt-Del key sequence is pressed.

To configure the system to ignore the Ctrl-Alt-Del key sequence
from the Graphical User Interface (GUI) instead of rebooting the system,
add or set logout to '' in
/etc/dconf/db/local.d/00-security-settings. For example:
[org/gnome/settings-daemon/plugins/media-keys]
logout=''
Once the settings have been added, add a lock to
/etc/dconf/db/local.d/locks/00-security-settings-lock to prevent
user modification. For example:
/org/gnome/settings-daemon/plugins/media-keys/logout
After the settings have been set, run dconf update.
```

## Rule id: disable\_ctrlaltdel\_reboot
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

## Rule id: disable\_ctrlaltdel\_burstaction
### Title: Disable Ctrl-Alt-Del Burst Action
### Description:

```
By default, SystemD will reboot the system if the Ctrl-Alt-Del
key sequence is pressed Ctrl-Alt-Delete more than 7 times in 2 seconds.

To configure the system to ignore the CtrlAltDelBurstAction

setting, add or modify the following to /etc/systemd/system.conf:
CtrlAltDelBurstAction=none
```

# SEE ALSO
**usg**(8)
