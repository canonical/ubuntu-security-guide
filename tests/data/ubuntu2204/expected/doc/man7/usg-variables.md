% USG-VARIABLES(7) usg-benchmarks 22.04.12
% Eduardo Barretto <eduardo.barretto@canonical.com>
% 19 September 2025

# NAME
usg-variables - usg variables list and description

# LIST OF VARIABLES AND THEIR DESCRIPTIONS
# List of variables
## Rule id: xccdf\_org.ssgproject.content\_value\_var\_aide\_scan\_notification\_email
### Title: Integrity Scan Notification Email Address
### Description:

```
Specify the email address for designated personnel if baseline
configurations are changed in an unauthorized manner.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ssh\_client\_rekey\_limit\_size
### Title: SSH client RekeyLimit - size
### Description:

```
Specify the size component of the rekey limit. This limit signifies amount
of data. After this amount of data is transferred through the connection,
the session key is renegotiated. The number is followed by K, M or G for
kilobytes, megabytes or gigabytes. Note that the RekeyLimit can be also
configured according to elapsed time.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ssh\_client\_rekey\_limit\_time
### Title: SSH client RekeyLimit - time
### Description:

```
Specify the time component of the rekey limit. The session key is
renegotiated after the defined amount of time passes. The number is followed
by units such as H or M for hours or minutes. Note that the RekeyLimit can
be also configured according to amount of transfered data.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_system\_crypto\_policy
### Title: The system-provided crypto policies
### Description:

```
Specify the crypto policy for the system.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mcafee\_antivirus\_definition\_expire
### Title: The age of McAfee defintion file before requiring updating
### Description:

```
Specify the amount of time (in seconds) before McAfee definition files need to be
updated.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_inactivity\_timeout\_value
### Title: Screensaver Inactivity timeout
### Description:

```
Choose allowed duration (in seconds) of inactive graphical sessions
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_screensaver\_lock\_delay
### Title: Screensaver Lock Delay
### Description:

```
Choose allowed duration (in seconds) after a screensaver becomes active before displaying an authentication prompt
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sudo\_dedicated\_group
### Title: Group name dedicated to the use of sudo
### Description:

```
Specify the name of the group that should own /usr/bin/sudo.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sudo\_logfile
### Title: Sudo - logfile value
### Description:

```
Specify the sudo logfile to use. The default value used here matches the example
location from CIS, which uses /var/log/sudo.log.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sudo\_passwd\_timeout
### Title: Sudo - passwd\_timeout value
### Description:

```
Defines the number of minutes before the sudo password prompt times out.
Defining 0 means no timeout. The default timeout value is 5 minutes.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sudo\_timestamp\_timeout
### Title: Sudo - timestamp\_timeout value
### Description:

```
Defines the number of minutes that can elapse before sudo will ask for a passwd again.
If set to a value less than 0 the user's time stamp will never expire. Defining 0 means always prompt for a 
password. The default timeout value is 5 minutes.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sudo\_umask
### Title: Sudo - umask value
### Description:

```
Specify the sudo umask to use. The actual umask value that is used is the union
of the user's umask and the sudo umask.
The default sudo umask is 0022. This guarantess sudo never lowers the umask when
running a command.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_authselect\_profile
### Title: Authselect  profile
### Description:

```
Specify the authselect profile to select
```

## Rule id: xccdf\_org.ssgproject.content\_value\_login\_banner\_text
### Title: Login Banner Verbiage
### Description:

```
Enter an appropriate login banner for your organization. Please note that new lines must
be expressed by the '\n' character and special characters like parentheses and quotation marks must be escaped with '\\'.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_hashing\_algorithm
### Title: Password Hashing algorithm
### Description:

```
Specify the system default encryption algorithm for encrypting passwords.
Defines the value set as ENCRYPT_METHOD in /etc/login.defs.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_unix\_remember
### Title: remember
### Description:

```
The last n passwords for each user are saved in
/etc/security/opasswd in order to force password change history and
keep the user from alternating between the same password too
frequently.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_passwords\_pam\_faillock\_deny
### Title: fail\_deny
### Description:

```
Number of failed login attempts before account lockout
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_passwords\_pam\_faillock\_dir
### Title: faillock directory
### Description:

```
The directory where the user files with the failure records are kept
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_passwords\_pam\_faillock\_fail\_interval
### Title: fail\_interval
### Description:

```
Interval for counting failed login attempts before account lockout
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_passwords\_pam\_faillock\_unlock\_time
### Title: fail\_unlock\_time
### Description:

```
Seconds before automatic unlocking or permanently locking after excessive failed logins
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_passwords\_pam\_tally2\_unlock\_time
### Title: tally2\_unlock\_time
### Description:

```
Seconds before automatic unlocking or permanently locking after excessive failed logins
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_delay
### Title: faildelay\_delay
### Description:

```
Delay next login attempt after a failed login
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_remember
### Title: pwhistory\_remember
### Description:

```
Prevent password re-use using password history lookup
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_remember\_control\_flag
### Title: PAM pwhistory remember - control flag
### Description:

```
'Specify the control flag required for password remember requirement. If multiple
values are allowed write them separated by commas as in "required,requisite",
for remediations the first value will be taken'
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_tally2
### Title: tally2
### Description:

```
Number of failed login attempts
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_dcredit
### Title: dcredit
### Description:

```
Minimum number of digits in password
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_dictcheck
### Title: dictcheck
### Description:

```
Prevent the use of dictionary words for passwords.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_difok
### Title: difok
### Description:

```
Minimum number of characters not present in old
password
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_lcredit
### Title: lcredit
### Description:

```
Minimum number of lower case in password
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_maxclassrepeat
### Title: maxclassrepeat
### Description:

```
Maximum Number of Consecutive Repeating Characters in a Password From the Same Character Class
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_maxrepeat
### Title: maxrepeat
### Description:

```
Maximum Number of Consecutive Repeating Characters in a Password
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_minclass
### Title: minclass
### Description:

```
Minimum number of categories of characters that must exist in a password
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_minlen
### Title: minlen
### Description:

```
Minimum number of characters in password
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_ocredit
### Title: ocredit
### Description:

```
Minimum number of other (special characters) in
password
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_retry
### Title: retry
### Description:

```
Number of retry attempts before erroring out
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_ucredit
### Title: ucredit
### Description:

```
Minimum number of upper case in password
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_logind\_session\_timeout
### Title: Login timeout for idle sessions
### Description:

```
Specify duration of allowed idle time.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_smartcard\_drivers
### Title: OpenSC Smart Card Drivers
### Description:

```
Choose the Smart Card Driver in use by your organization.
For DoD, choose the cac driver.
If your driver is not listed and you don't want to use the
default driver, use the other option and
manually specify your driver.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_authorized\_local\_users\_regex
### Title: Accounts Authorized Local Users on the Operating System
### Description:

```
List the user accounts that are authorized locally on the operating system. This list
includes both users requried by the operating system and by the installed applications.
Depending on the Operating System distribution, version, software groups and applications,
the user list is different and can be customized with scap-workbench.
OVAL regular expression is used for the user list.
The list starts with '^' and ends with '$' so that it matches exactly the
username, not any string that includes the username. Users are separated with '|'.
For example, three users: bin, oracle and sapadm are allowed, then the list is
^(bin|oracle|sapadm)$. The user root is the only user that is hard coded
in OVAL that is always allowed on the operating system.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_account\_disable\_inactivity
### Title: number of days after the last login of the user when the user will be locked out
### Description:

```
'This option is specific for the auth or account phase. It specifies the number of days after
the last login of the user when the user will be locked out by the pam_lastlog module.'
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_account\_disable\_post\_pw\_expiration
### Title: number of days after a password expires until the account is permanently disabled
### Description:

```
The number of days to wait after a password expires, until the account will be permanently disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_maximum\_age\_login\_defs
### Title: maximum password age
### Description:

```
Maximum age of password in days
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_minimum\_age\_login\_defs
### Title: minimum password age
### Description:

```
Minimum age of password in days
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_password\_minlen\_login\_defs
### Title: minimum password length
### Description:

```
Minimum number of characters in password
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_password\_warn\_age\_login\_defs
### Title: warning days before password expires
### Description:

```
The number of days' warning given before a password expires.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_unix\_rounds
### Title: Password Hashing algorithm
### Description:

```
Specify the number of SHA rounds for the system password encryption algorithm.
Defines the value set in /etc/pam.d/system-auth and /etc/pam.d/password-auth
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_pam\_wheel\_group\_for\_su
### Title: Group Name Used by pam\_wheel Group Parameter
### Description:

```
pam_wheel module has a parameter called group, which controls which groups
can access the su command.
This variable holds the valid value for the parameter.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_fail\_delay
### Title: Maximum login attempts delay
### Description:

```
Maximum time in seconds between fail login attempts before re-prompting.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_max\_concurrent\_login\_sessions
### Title: Maximum concurrent login sessions
### Description:

```
Maximum number of concurrent sessions by a user
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_tmout
### Title: Account Inactivity Timeout (seconds)
### Description:

```
In an interactive shell, the value is interpreted as the
number of seconds to wait for input after issuing the primary prompt.
Bash terminates after waiting for that number of seconds if input does
not arrive.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_user\_initialization\_files\_regex
### Title: Interactive users initialization files
### Description:

```
'A regular expression describing a list of file names
for files that are sourced at login time for interactive users'
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_accounts\_user\_umask
### Title: Sensible umask
### Description:

```
Enter default user umask
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_apparmor\_mode
### Title: AppArmor profiles mode
### Description:

```
enforce - Set all AppArmor profiles to enforce mode
complain - Set all AppArmor profiles to complain mode
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_l1tf\_options
### Title: L1TF vulnerability mitigation
### Description:

```
Defines the L1TF vulneratility mitigations to employ.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mds\_options
### Title: MDS vulnerability mitigation
### Description:

```
Defines the MDS vulneratility mitigation to employ.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_rng\_core\_default\_quality
### Title: Confidence level on Hardware Random Number Generator
### Description:

```
Defines the level of trust on the hardware random number generators available in the
system and the percentage of entropy to credit.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_spec\_store\_bypass\_disable\_options
### Title: Spec Store Bypass Mitigation
### Description:

```
This controls how the Speculative Store Bypass (SSB) vulnerability is mitigated.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_kernel\_config\_module\_sig\_hash
### Title: Hash function for kernel module signing
### Description:

```
The hash function to use when signing modules during kernel build process.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_kernel\_config\_module\_sig\_key
### Title: Key and certificate for kernel module signing
### Description:

```
The private key and certificate to use when signing modules during kernel build process.
On systems where the OpenSSL ENGINE_pkcs11 is functional — a PKCS#11 URI as defined by RFC7512
In the latter case, the PKCS#11 URI should reference both a certificate and a private key.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_kernel\_config\_panic\_timeout
### Title: Kernel panic timeout
### Description:

```
The time, in seconds, to wait until a reboot occurs.
If the value is 0 the system never reboots.
If the value is less than 0 the system reboots immediately.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_file\_owner\_logfiles\_value
### Title: User who owns log files
### Description:

```
Specify user owner of all logfiles specified in
/etc/rsyslog.conf.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_rsyslog\_remote\_loghost\_address
### Title: Remote Log Server
### Description:

```
Specify an URI or IP address of a remote host where the log messages will be sent and stored.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysconfig\_network\_IPV6\_AUTOCONF\_value
### Title: IPV6\_AUTOCONF
### Description:

```
Toggle global IPv6 auto-configuration (only, if global
forwarding is disabled)
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_all\_accept\_ra\_defrtr\_value
### Title: net.ipv6.conf.all.accept\_ra\_defrtr
### Description:

```
Accept default router in router advertisements?
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_all\_accept\_ra\_pinfo\_value
### Title: net.ipv6.conf.all.accept\_ra\_pinfo
### Description:

```
Accept prefix information in router advertisements?
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_all\_accept\_ra\_rtr\_pref\_value
### Title: net.ipv6.conf.all.accept\_ra\_rtr\_pref
### Description:

```
Accept router preference in router advertisements?
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_all\_accept\_ra\_value
### Title: net.ipv6.conf.all.accept\_ra
### Description:

```
Accept all router advertisements?
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_all\_accept\_redirects\_value
### Title: net.ipv6.conf.all.accept\_redirects
### Description:

```
Toggle ICMP Redirect Acceptance
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_all\_accept\_source\_route\_value
### Title: net.ipv6.conf.all.accept\_source\_route
### Description:

```
Trackers could be using source-routed packets to
generate traffic that seems to be intra-net, but actually was
created outside and has been redirected.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_all\_autoconf\_value
### Title: net.ipv6.conf.all.autoconf
### Description:

```
Enable auto configuration on IPv6 interfaces
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_all\_forwarding\_value
### Title: net.ipv6.conf.all.forwarding
### Description:

```
Toggle IPv6 Forwarding
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_all\_max\_addresses\_value
### Title: net.ipv6.conf.all.max\_addresses
### Description:

```
Maximum number of autoconfigured IPv6 addresses
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_all\_router\_solicitations\_value
### Title: net.ipv6.conf.all.router\_solicitations
### Description:

```
Accept all router solicitations?
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_default\_accept\_ra\_defrtr\_value
### Title: net.ipv6.conf.default.accept\_ra\_defrtr
### Description:

```
Accept default router in router advertisements?
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_default\_accept\_ra\_pinfo\_value
### Title: net.ipv6.conf.default.accept\_ra\_pinfo
### Description:

```
Accept prefix information in router advertisements?
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_default\_accept\_ra\_rtr\_pref\_value
### Title: net.ipv6.conf.default.accept\_ra\_rtr\_pref
### Description:

```
Accept router preference in router advertisements?
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_default\_accept\_ra\_value
### Title: net.ipv6.conf.default.accept\_ra
### Description:

```
Accept default router advertisements by default?
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_default\_accept\_redirects\_value
### Title: net.ipv6.conf.default.accept\_redirects
### Description:

```
Toggle ICMP Redirect Acceptance By Default
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_default\_accept\_source\_route\_value
### Title: net.ipv6.conf.default.accept\_source\_route
### Description:

```
Trackers could be using source-routed packets to
generate traffic that seems to be intra-net, but actually was
created outside and has been redirected.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_default\_autoconf\_value
### Title: net.ipv6.conf.default.autoconf
### Description:

```
Enable auto configuration on IPv6 interfaces
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_default\_forwarding\_value
### Title: net.ipv6.conf.default.forwarding
### Description:

```
Toggle IPv6 default Forwarding
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_default\_max\_addresses\_value
### Title: net.ipv6.conf.default.max\_addresses
### Description:

```
Maximum number of autoconfigured IPv6 addresses
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_default\_router\_solicitations\_value
### Title: net.ipv6.conf.default.router\_solicitations
### Description:

```
Accept all router solicitations by default?
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_all\_accept\_redirects\_value
### Title: net.ipv4.conf.all.accept\_redirects
### Description:

```
Disable ICMP Redirect Acceptance
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_all\_accept\_source\_route\_value
### Title: net.ipv4.conf.all.accept\_source\_route
### Description:

```
Trackers could be using source-routed packets to
generate traffic that seems to be intra-net, but actually was
created outside and has been redirected.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_all\_arp\_filter\_value
### Title: net.ipv4.conf.default.arp\_filter
### Description:

```
Controls whether the ARP filter is enabled or not.

1 - Allows you to have multiple network interfaces on the same subnet, and have the ARPs for each
interface be answered based on whether or not the kernel would route a packet from the ARP’d IP out that interface.
In other words it allows control of which cards (usually 1) will respond to an ARP request.

0 - (default) The kernel can respond to arp requests with addresses from other interfaces.
This may seem wrong but it usually makes sense, because it increases the chance of successful communication.
IP addresses are owned by the complete host on Linux, not by particular interfaces.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_all\_arp\_ignore\_value
### Title: net.ipv4.conf.default.arp\_ignore
### Description:

```
Control the response modes for ARP queries that resolve local target IP addresses:

0 - (default): reply for any local target IP address, configured on any interface
1 - reply only if the target IP address is local address configured on the incoming interface
2 - reply only if the target IP address is local address configured on the incoming interface and both with the sender’s IP address are part from same subnet on this interface
3 - do not reply for local addresses configured with scope host, only resolutions for global and link addresses are replied
4-7 - reserved
8 - do not reply for all local addresses
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_all\_forwarding\_value
### Title: net.ipv4.conf.all.forwarding
### Description:

```
Toggle IPv4 Forwarding
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_all\_log\_martians\_value
### Title: net.ipv4.conf.all.log\_martians
### Description:

```
Disable so you don't Log Spoofed Packets, Source
Routed Packets, Redirect Packets
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_all\_rp\_filter\_value
### Title: net.ipv4.conf.all.rp\_filter
### Description:

```
Enable to enforce sanity checking, also called ingress
filtering or egress filtering. The point is to drop a packet if the
source and destination IP addresses in the IP header do not make
sense when considered in light of the physical interface on which
it arrived.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_all\_secure\_redirects\_value
### Title: net.ipv4.conf.all.secure\_redirects
### Description:

```
Enable to prevent hijacking of routing path by only
allowing redirects from gateways known in routing
table. Disable to refuse acceptance of secure ICMP redirected packets on all interfaces.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_all\_shared\_media\_value
### Title: net.ipv4.conf.all.shared\_media
### Description:

```
Controls whether the system can send (router) or accept (host) RFC1620 shared media redirects.
shared_media for the interface will be enabled if at least one of conf/{all,interface}/shared_media
is set to TRUE, it will be disabled otherwise.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_default\_accept\_redirects\_value
### Title: net.ipv4.conf.default.accept\_redirects
### Description:

```
Disable ICMP Redirect Acceptance?
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_default\_accept\_source\_route\_value
### Title: net.ipv4.conf.default.accept\_source\_route
### Description:

```
Disable IP source routing?
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_default\_log\_martians\_value
### Title: net.ipv4.conf.default.log\_martians
### Description:

```
Disable so you don't Log Spoofed Packets, Source
Routed Packets, Redirect Packets
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_default\_rp\_filter\_value
### Title: net.ipv4.conf.default.rp\_filter
### Description:

```
Enables source route verification
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_default\_secure\_redirects\_value
### Title: net.ipv4.conf.default.secure\_redirects
### Description:

```
Enable to prevent hijacking of routing path by only
allowing redirects from gateways known in routing
table. Disable to refuse acceptance of secure ICMP redirected packages by default.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_conf\_default\_shared\_media\_value
### Title: net.ipv4.conf.default.shared\_media
### Description:

```
Controls whether the system can send(router) or accept(host) RFC1620 shared media redirects.
shared_media for the interface will be enabled if at least one of conf/{all,interface}/shared_media
is set to TRUE, it will be disabled otherwise.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_icmp\_echo\_ignore\_broadcasts\_value
### Title: net.ipv4.icmp\_echo\_ignore\_broadcasts
### Description:

```
Ignore all ICMP ECHO and TIMESTAMP requests sent to it
via broadcast/multicast
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_icmp\_ignore\_bogus\_error\_responses\_value
### Title: net.ipv4.icmp\_ignore\_bogus\_error\_responses
### Description:

```
Enable to prevent unnecessary logging
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_tcp\_invalid\_ratelimit\_value
### Title: net.ipv4.tcp\_invalid\_ratelimit
### Description:

```
Configure  the maximal rate for sending duplicate acknowledgments in
response to incoming invalid TCP packets.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_tcp\_rfc1337\_value
### Title: net.ipv4.tcp\_rfc1337
### Description:

```
Enable to enable TCP behavior conformant with RFC 1337
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_tcp\_syncookies\_value
### Title: net.ipv4.tcp\_syncookies
### Description:

```
Enable to turn on TCP SYN Cookie
Protection
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nftable\_master\_config\_file
### Title: Nftables Master configuration file
### Description:

```
The file which contains top level configuration for nftables service, and with which,
the service is started.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nftables\_base\_chain\_hooks
### Title: Nftables Base Chain Hooks
### Description:

```
The possible hooks which can be used to configure the base chain are:
ingress (only in netdev family since Linux kernel 4.2, and inet family since Linux kernel 5.10): 
sees packets immediately after they are passed up from the NIC driver, before even prerouting. 
prerouting sees all incoming packets, before any routing decision has been made. 
Packets may be addressed to the local or remote systems.
input sees incoming packets that are addressed to and have now been routed 
to the local system and processes running there.
forward sees incoming packets that are not addressed to the local system.
output sees packets that originated from processes in the local machine.
postrouting sees all packets after routing, just before they leave the 
local system.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nftables\_base\_chain\_names
### Title: Nftables Chain Names
### Description:

```
The rules in nftables are attached to chains. Unlike in iptables, 
there are no predefined chains like INPUT, OUTPUT, etc. Instead, 
to filter packets at a particular processing step, a base chain with a 
chosen name should be created, and attached it to the appropriate 
Netfilter hook. 
 
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nftables\_base\_chain\_policies
### Title: Nftables Base Chain Policies
### Description:

```
This is the default verdict that will be applied to packets reaching the end of the chain 
(i.e, no more rules to be evaluated against).
Currently there are 2 policies: 
accept this verdict means that the packet will keep traversing the network stack.
drop this verdict means that the packet is discarded if the packet reaches the end 
of the base chain.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nftables\_base\_chain\_priorities
### Title: Nftables Base Chain Priorities
### Description:

```
Each nftables base chain is assigned a priority that defines its ordering 
among other base chains, flowtables, and Netfilter internal operations at 
the same hook. For example, a chain on the prerouting hook with priority 
-300 will be placed before connection tracking operations. 
Netfilter Internal Priority for inet, ip, ip6:
NF_IP_PRI_RAW_BEFORE_DEFRAG Typical hooks: prerouting; nft Keyword: n/a; Description: n/a
NF_IP_PRI_CONNTRACK_DEFRAG Typical hooks: prerouting; nft Keyword: n/a; Description: Packet defragmentation / datagram reassembly 
NF_IP_PRI_RAW Typical hooks: all; nft Keyword: raw; Description:  Typical hooks: prerouting; nft Keyword: n/a; Description: Traditional priority of 
the raw table placed before connection tracking operation 
NF_IP_PRI_SELINUX_FIRST Typical hooks: n/a; nft Keyword: n/a; Description: SELinux operations  
NF_IP_PRI_CONNTRACK Typical hooks: prerouting, output;nft Keyword: n/a; Description: Connection tracking processes run early in prerouting and 
output hooks to associate packets with tracked connections.
NF_IP_PRI_MANGLE Typical hooks: all;nft Keyword: mangle; Description: Mangle operation
NF_IP_PRI_NAT_DST Typical hooks: prerouting;nft Keyword: dstnat; Description: Destination NAT
NF_IP_PRI_FILTER Typical hooks: all;nft Keyword: filter; Description: Filtering operation, the filter table 
NF_IP_PRI_SECURITY Typical hooks: all;nft Keyword: security; Description: Place of security table, where secmark can be set for example 
NF_IP_PRI_NAT_SRC Typical hooks: postrouting;nft Keyword: srcnat; Description: Source NAT
NF_IP_PRI_SELINUX_LAST Typical hooks: postrouting;nft Keyword: n/a; Description: SELinux at packet exit
NF_IP_PRI_CONNTRACK_HELPER Typical hooks: postrouting;nft Keyword: n/a; Description: Connection tracking helpers, which identify expected and 
related packets. 
NF_IP_PRI_CONNTRACK_CONFIRM Typical hooks: input,postrouting;nft Keyword: n/a; Description: Connection tracking adds new tracked connections 
at final step in input and postrouting hooks. 
Netfilter Internal Priority for bridge:
NF_BR_PRI_NAT_DST_BRIDGED Typical hooks: prerouting; nft Keyword: n/a; Description: n/a
NF_BR_PRI_FILTER_BRIDGED Typical hooks: all;nft Keyword: filter; Description: n/a
NF_BR_PRI_BRNF Typical hooks: n/a;nft Keyword: n/a; Description: n/a
NF_BR_PRI_NAT_DST_OTHER Typical hooks: output;nft Keyword: out; Description: n/a
NF_BR_PRI_FILTER_OTHER Typical hooks: n/a;nft Keyword: n/a; Description: n/a
NF_BR_PRI_NAT_SRC Typical hooks: postrouting;nft Keyword: srcnat; Description: n/a
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nftables\_base\_chain\_types
### Title: Nftables Base Chain Types
### Description:

```
Base chains are those that are registered into the Netfilter hooks, 
i.e. these chains see packets flowing through the Linux TCP/IP stack.
The possible chain types are:
filter, which is used to filter packets. This is supported by 
the arp, bridge, ip, ip6 and inet table families.
route, which is used to reroute packets if any relevant IP 
header field or the packet mark is modified. This chain type provides 
equivalent semantics to the mangle table but only for the output hook 
(for other hooks use type filter instead). This is supported by the 
ip, ip6 and inet table families.
nat, which is used to perform Networking Address Translation (NAT). 
Only the first packet of a given flow hits this chain; subsequent packets bypass it. 
This chain should be never used for filtering. The nat chain type 
is supported by the ip, ip6 and inet table families.
 
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nftables\_family
### Title: Nftables Families
### Description:

```
Netfilter enables filtering at multiple networking levels. With iptables there 
is a separate tool for each level: iptables, ip6tables, arptables, ebtables. 
With nftables the multiple networking levels are abstracted into families, 
all of which are served  by the single tool nft. 
ipTables of this family see IPv4 traffic/packets. 
ip6Tables of this family see IPv6 traffic/packets.
inetTables of this family see both IPv4 and IPv6 traffic/packets, 
simplifying dual stack support. 
arpTables of this family see ARP-level (i.e, L2) traffic, before 
any L3 handling is done by the kernel. 
bridgeTables of this family see traffic/packets traversing bridges 
(i.e. switching). No assumptions are made about L3 protocols. 
netdevThe netdev family is different from the others in that it 
is used to create base chains attached to a single network interface. Such 
base chains see all network traffic on the specified interface, with no 
assumptions about L2 or L3 protocols. Therefore you can filter ARP traffic from here. 
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nftables\_table
### Title: Nftables Tables
### Description:

```
Tables in nftables hold chains. Each table only has one address family and only applies 
to packets of this family. Tables can have one of six families.
 
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mount\_option\_proc\_hidepid
### Title: Value for hidepid option
### Description:

```
The hidepid mount option is applicable to /proc and is used to control who can access
the information in /proc/[pid] directories. The option can have one of the following
values:
0: Everybody may access all /proc/[pid] directories.
1: Users may not access files and subdirectories inside any /proc/[pid] directories
   but their own. The /proc/[pid] directories themselves remain visible.
2: Same as for mode 1, but in addition the /proc/[pid] directories belonging to other
   users become invisible.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_removable\_partition
### Title: Removable Partition
### Description:

```
This value is used by the checks mount_option_nodev_removable_partitions, mount_option_nodev_removable_partitions,
and mount_option_nodev_removable_partitions to ensure that the correct mount options are set on partitions mounted from
removable media such as CD-ROMs, USB keys, and floppy drives. This value should be modified to reflect any removable
partitions that are required on the local system.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_kernel\_unprivileged\_bpf\_disabled\_value
### Title: kernel.unprivileged\_bpf\_disabled
### Description:

```
Prevent unprivileged processes from using the bpf() syscall.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_umask\_for\_daemons
### Title: daemon umask
### Description:

```
Enter umask for daemons
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_kernel\_kptr\_restrict\_value
### Title: kernel.kptr\_restrict
### Description:

```
Configure exposition of kernel pointer addresses 
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_slub\_debug\_options
### Title: slub\_debug - debug options
### Description:

```
Defines the debug options to use in slub_debug kernel command line argument.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinux\_policy\_name
### Title: SELinux policy
### Description:

```
Type of policy in use. Possible values are:
targeted - Only targeted network daemons are protected.
strict - Full SELinux protection.
mls - Multiple levels of security
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinux\_state
### Title: SELinux state
### Description:

```
enforcing - SELinux security policy is enforced.
permissive - SELinux prints warnings instead of enforcing.
disabled - SELinux is fully disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_abrt\_anon\_write
### Title: abrt\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_abrt\_handle\_event
### Title: abrt\_handle\_event SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_abrt\_upload\_watch\_anon\_write
### Title: abrt\_upload\_watch\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_antivirus\_can\_scan\_system
### Title: antivirus\_can\_scan\_system SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_antivirus\_use\_jit
### Title: antivirus\_use\_jit SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditadm\_exec\_content
### Title: auditadm\_exec\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_authlogin\_nsswitch\_use\_ldap
### Title: authlogin\_nsswitch\_use\_ldap SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_authlogin\_radius
### Title: authlogin\_radius SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_authlogin\_yubikey
### Title: authlogin\_yubikey SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_awstats\_purge\_apache\_log\_files
### Title: awstats\_purge\_apache\_log\_files SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_boinc\_execmem
### Title: boinc\_execmem SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cdrecord\_read\_content
### Title: cdrecord\_read\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cluster\_can\_network\_connect
### Title: cluster\_can\_network\_connect SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cluster\_manage\_all\_files
### Title: cluster\_manage\_all\_files SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cluster\_use\_execmem
### Title: cluster\_use\_execmem SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cobbler\_anon\_write
### Title: cobbler\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cobbler\_can\_network\_connect
### Title: cobbler\_can\_network\_connect SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cobbler\_use\_cifs
### Title: cobbler\_use\_cifs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cobbler\_use\_nfs
### Title: cobbler\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_collectd\_tcp\_network\_connect
### Title: collectd\_tcp\_network\_connect SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_condor\_tcp\_network\_connect
### Title: condor\_tcp\_network\_connect SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_conman\_can\_network
### Title: conman\_can\_network SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_container\_connect\_any
### Title: container\_connect\_any SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cron\_can\_relabel
### Title: cron\_can\_relabel SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cron\_system\_cronjob\_use\_shares
### Title: cron\_system\_cronjob\_use\_shares SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cron\_userdomain\_transition
### Title: cron\_userdomain\_transition SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cups\_execmem
### Title: cups\_execmem SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_cvs\_read\_shadow
### Title: cvs\_read\_shadow SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_daemons\_dump\_core
### Title: daemons\_dump\_core SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_daemons\_enable\_cluster\_mode
### Title: daemons\_enable\_cluster\_mode SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_daemons\_use\_tcp\_wrapper
### Title: daemons\_use\_tcp\_wrapper SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_daemons\_use\_tty
### Title: daemons\_use\_tty SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_dbadm\_exec\_content
### Title: dbadm\_exec\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_dbadm\_manage\_user\_files
### Title: dbadm\_manage\_user\_files SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_dbadm\_read\_user\_files
### Title: dbadm\_read\_user\_files SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_deny\_execmem
### Title: deny\_execmem SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_deny\_ptrace
### Title: deny\_ptrace SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_dhcpc\_exec\_iptables
### Title: dhcpc\_exec\_iptables SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_dhcpd\_use\_ldap
### Title: dhcpd\_use\_ldap SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_domain\_fd\_use
### Title: domain\_fd\_use SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_domain\_kernel\_load\_modules
### Title: domain\_kernel\_load\_modules SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_entropyd\_use\_audio
### Title: entropyd\_use\_audio SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_exim\_can\_connect\_db
### Title: exim\_can\_connect\_db SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_exim\_manage\_user\_files
### Title: exim\_manage\_user\_files SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_exim\_read\_user\_files
### Title: exim\_read\_user\_files SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_fcron\_crond
### Title: fcron\_crond SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_fenced\_can\_network\_connect
### Title: fenced\_can\_network\_connect SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_fenced\_can\_ssh
### Title: fenced\_can\_ssh SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_fips\_mode
### Title: fips\_mode SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ftpd\_anon\_write
### Title: ftpd\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ftpd\_connect\_all\_unreserved
### Title: ftpd\_connect\_all\_unreserved SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ftpd\_connect\_db
### Title: ftpd\_connect\_db SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ftpd\_full\_access
### Title: ftpd\_full\_access SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ftpd\_use\_cifs
### Title: ftpd\_use\_cifs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ftpd\_use\_fusefs
### Title: ftpd\_use\_fusefs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ftpd\_use\_nfs
### Title: ftpd\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ftpd\_use\_passive\_mode
### Title: ftpd\_use\_passive\_mode SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_git\_cgi\_enable\_homedirs
### Title: git\_cgi\_enable\_homedirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_git\_cgi\_use\_cifs
### Title: git\_cgi\_use\_cifs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_git\_cgi\_use\_nfs
### Title: git\_cgi\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_git\_session\_bind\_all\_unreserved\_ports
### Title: git\_session\_bind\_all\_unreserved\_ports SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_git\_session\_users
### Title: git\_session\_users SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_git\_system\_enable\_homedirs
### Title: git\_system\_enable\_homedirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_git\_system\_use\_cifs
### Title: git\_system\_use\_cifs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_git\_system\_use\_nfs
### Title: git\_system\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_gitosis\_can\_sendmail
### Title: gitosis\_can\_sendmail SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_glance\_api\_can\_network
### Title: glance\_api\_can\_network SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_glance\_use\_execmem
### Title: glance\_use\_execmem SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_glance\_use\_fusefs
### Title: glance\_use\_fusefs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_global\_ssp
### Title: global\_ssp SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_gluster\_anon\_write
### Title: gluster\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_gluster\_export\_all\_ro
### Title: gluster\_export\_all\_ro SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_gluster\_export\_all\_rw
### Title: gluster\_export\_all\_rw SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_gpg\_web\_anon\_write
### Title: gpg\_web\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_gssd\_read\_tmp
### Title: gssd\_read\_tmp SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_guest\_exec\_content
### Title: guest\_exec\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_haproxy\_connect\_any
### Title: haproxy\_connect\_any SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_anon\_write
### Title: httpd\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_builtin\_scripting
### Title: httpd\_builtin\_scripting SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_can\_check\_spam
### Title: httpd\_can\_check\_spam SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_can\_connect\_ftp
### Title: httpd\_can\_connect\_ftp SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_can\_connect\_ldap
### Title: httpd\_can\_connect\_ldap SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_can\_connect\_mythtv
### Title: httpd\_can\_connect\_mythtv SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_can\_connect\_zabbix
### Title: httpd\_can\_connect\_zabbix SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_can\_network\_connect
### Title: httpd\_can\_network\_connect SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_can\_network\_connect\_cobbler
### Title: httpd\_can\_network\_connect\_cobbler SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_can\_network\_connect\_db
### Title: httpd\_can\_network\_connect\_db SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_can\_network\_memcache
### Title: httpd\_can\_network\_memcache SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_can\_network\_relay
### Title: httpd\_can\_network\_relay SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_can\_sendmail
### Title: httpd\_can\_sendmail SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_dbus\_avahi
### Title: httpd\_dbus\_avahi SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_dbus\_sssd
### Title: httpd\_dbus\_sssd SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_dontaudit\_search\_dirs
### Title: httpd\_dontaudit\_search\_dirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_enable\_cgi
### Title: httpd\_enable\_cgi SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_enable\_ftp\_server
### Title: httpd\_enable\_ftp\_server SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_enable\_homedirs
### Title: httpd\_enable\_homedirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_execmem
### Title: httpd\_execmem SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_graceful\_shutdown
### Title: httpd\_graceful\_shutdown SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_manage\_ipa
### Title: httpd\_manage\_ipa SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_mod\_auth\_ntlm\_winbind
### Title: httpd\_mod\_auth\_ntlm\_winbind SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_mod\_auth\_pam
### Title: httpd\_mod\_auth\_pam SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_read\_user\_content
### Title: httpd\_read\_user\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_run\_ipa
### Title: httpd\_run\_ipa SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_run\_preupgrade
### Title: httpd\_run\_preupgrade SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_run\_stickshift
### Title: httpd\_run\_stickshift SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_serve\_cobbler\_files
### Title: httpd\_serve\_cobbler\_files SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_setrlimit
### Title: httpd\_setrlimit SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_ssi\_exec
### Title: httpd\_ssi\_exec SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_sys\_script\_anon\_write
### Title: httpd\_sys\_script\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_tmp\_exec
### Title: httpd\_tmp\_exec SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_tty\_comm
### Title: httpd\_tty\_comm SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_unified
### Title: httpd\_unified SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_use\_cifs
### Title: httpd\_use\_cifs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_use\_fusefs
### Title: httpd\_use\_fusefs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_use\_gpg
### Title: httpd\_use\_gpg SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_use\_nfs
### Title: httpd\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_use\_openstack
### Title: httpd\_use\_openstack SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_use\_sasl
### Title: httpd\_use\_sasl SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_verify\_dns
### Title: httpd\_verify\_dns SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_icecast\_use\_any\_tcp\_ports
### Title: icecast\_use\_any\_tcp\_ports SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_irc\_use\_any\_tcp\_ports
### Title: irc\_use\_any\_tcp\_ports SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_irssi\_use\_full\_network
### Title: irssi\_use\_full\_network SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_kdumpgui\_run\_bootloader
### Title: kdumpgui\_run\_bootloader SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_kerberos\_enabled
### Title: kerberos\_enabled SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ksmtuned\_use\_cifs
### Title: ksmtuned\_use\_cifs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ksmtuned\_use\_nfs
### Title: ksmtuned\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_logadm\_exec\_content
### Title: logadm\_exec\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_logging\_syslogd\_can\_sendmail
### Title: logging\_syslogd\_can\_sendmail SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_logging\_syslogd\_run\_nagios\_plugins
### Title: logging\_syslogd\_run\_nagios\_plugins SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_logging\_syslogd\_use\_tty
### Title: logging\_syslogd\_use\_tty SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_login\_console\_enabled
### Title: login\_console\_enabled SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_logrotate\_use\_nfs
### Title: logrotate\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_logwatch\_can\_network\_connect\_mail
### Title: logwatch\_can\_network\_connect\_mail SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_lsmd\_plugin\_connect\_any
### Title: lsmd\_plugin\_connect\_any SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mailman\_use\_fusefs
### Title: mailman\_use\_fusefs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mcelog\_client
### Title: mcelog\_client SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mcelog\_exec\_scripts
### Title: mcelog\_exec\_scripts SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mcelog\_foreground
### Title: mcelog\_foreground SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mcelog\_server
### Title: mcelog\_server SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_minidlna\_read\_generic\_user\_content
### Title: minidlna\_read\_generic\_user\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mmap\_low\_allowed
### Title: mmap\_low\_allowed SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mock\_enable\_homedirs
### Title: mock\_enable\_homedirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mount\_anyfile
### Title: mount\_anyfile SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mozilla\_plugin\_bind\_unreserved\_ports
### Title: mozilla\_plugin\_bind\_unreserved\_ports SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mozilla\_plugin\_can\_network\_connect
### Title: mozilla\_plugin\_can\_network\_connect SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mozilla\_plugin\_use\_bluejeans
### Title: mozilla\_plugin\_use\_bluejeans SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mozilla\_plugin\_use\_gps
### Title: mozilla\_plugin\_use\_gps SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mozilla\_plugin\_use\_spice
### Title: mozilla\_plugin\_use\_spice SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mozilla\_read\_content
### Title: mozilla\_read\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mpd\_enable\_homedirs
### Title: mpd\_enable\_homedirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mpd\_use\_cifs
### Title: mpd\_use\_cifs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mpd\_use\_nfs
### Title: mpd\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mplayer\_execstack
### Title: mplayer\_execstack SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_mysql\_connect\_any
### Title: mysql\_connect\_any SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nagios\_run\_pnp4nagios
### Title: nagios\_run\_pnp4nagios SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nagios\_run\_sudo
### Title: nagios\_run\_sudo SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_named\_tcp\_bind\_http\_port
### Title: named\_tcp\_bind\_http\_port SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_named\_write\_master\_zones
### Title: named\_write\_master\_zones SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_neutron\_can\_network
### Title: neutron\_can\_network SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nfs\_export\_all\_ro
### Title: nfs\_export\_all\_ro SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nfs\_export\_all\_rw
### Title: nfs\_export\_all\_rw SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nfsd\_anon\_write
### Title: nfsd\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nis\_enabled
### Title: nis\_enabled SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nscd\_use\_shm
### Title: nscd\_use\_shm SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_openshift\_use\_nfs
### Title: openshift\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_openvpn\_can\_network\_connect
### Title: openvpn\_can\_network\_connect SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_openvpn\_enable\_homedirs
### Title: openvpn\_enable\_homedirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_openvpn\_run\_unconfined
### Title: openvpn\_run\_unconfined SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_pcp\_bind\_all\_unreserved\_ports
### Title: pcp\_bind\_all\_unreserved\_ports SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_pcp\_read\_generic\_logs
### Title: pcp\_read\_generic\_logs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_piranha\_lvs\_can\_network\_connect
### Title: piranha\_lvs\_can\_network\_connect SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_polipo\_connect\_all\_unreserved
### Title: polipo\_connect\_all\_unreserved SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_polipo\_session\_bind\_all\_unreserved\_ports
### Title: polipo\_session\_bind\_all\_unreserved\_ports SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_polipo\_session\_users
### Title: polipo\_session\_users SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_polipo\_use\_cifs
### Title: polipo\_use\_cifs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_polipo\_use\_nfs
### Title: polipo\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_polyinstantiation\_enabled
### Title: polyinstantiation\_enabled SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_postfix\_local\_write\_mail\_spool
### Title: postfix\_local\_write\_mail\_spool SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_postgresql\_can\_rsync
### Title: postgresql\_can\_rsync SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_postgresql\_selinux\_transmit\_client\_label
### Title: postgresql\_selinux\_transmit\_client\_label SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_postgresql\_selinux\_unconfined\_dbadm
### Title: postgresql\_selinux\_unconfined\_dbadm SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_postgresql\_selinux\_users\_ddl
### Title: postgresql\_selinux\_users\_ddl SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_pppd\_can\_insmod
### Title: pppd\_can\_insmod SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_pppd\_for\_user
### Title: pppd\_for\_user SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_privoxy\_connect\_any
### Title: privoxy\_connect\_any SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_prosody\_bind\_http\_port
### Title: prosody\_bind\_http\_port SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_puppetagent\_manage\_all\_files
### Title: puppetagent\_manage\_all\_files SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_puppetmaster\_use\_db
### Title: puppetmaster\_use\_db SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_racoon\_read\_shadow
### Title: racoon\_read\_shadow SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_rsync\_anon\_write
### Title: rsync\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_rsync\_client
### Title: rsync\_client SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_rsync\_export\_all\_ro
### Title: rsync\_export\_all\_ro SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_rsync\_full\_access
### Title: rsync\_full\_access SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_samba\_create\_home\_dirs
### Title: samba\_create\_home\_dirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_samba\_domain\_controller
### Title: samba\_domain\_controller SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_samba\_enable\_home\_dirs
### Title: samba\_enable\_home\_dirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_samba\_export\_all\_ro
### Title: samba\_export\_all\_ro SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_samba\_export\_all\_rw
### Title: samba\_export\_all\_rw SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_samba\_load\_libgfapi
### Title: samba\_load\_libgfapi SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_samba\_portmapper
### Title: samba\_portmapper SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_samba\_run\_unconfined
### Title: samba\_run\_unconfined SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_samba\_share\_fusefs
### Title: samba\_share\_fusefs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_samba\_share\_nfs
### Title: samba\_share\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sanlock\_use\_fusefs
### Title: sanlock\_use\_fusefs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sanlock\_use\_nfs
### Title: sanlock\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sanlock\_use\_samba
### Title: sanlock\_use\_samba SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_saslauthd\_read\_shadow
### Title: saslauthd\_read\_shadow SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_secadm\_exec\_content
### Title: secadm\_exec\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_secure\_mode
### Title: secure\_mode SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_secure\_mode\_insmod
### Title: secure\_mode\_insmod SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_secure\_mode\_policyload
### Title: secure\_mode\_policyload SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinuxuser\_direct\_dri\_enabled
### Title: selinuxuser\_direct\_dri\_enabled SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinuxuser\_execheap
### Title: selinuxuser\_execheap SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinuxuser\_execmod
### Title: selinuxuser\_execmod SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinuxuser\_execstack
### Title: selinuxuser\_execstack SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinuxuser\_mysql\_connect\_enabled
### Title: selinuxuser\_mysql\_connect\_enabled SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinuxuser\_ping
### Title: selinuxuser\_ping SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinuxuser\_postgresql\_connect\_enabled
### Title: selinuxuser\_postgresql\_connect\_enabled SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinuxuser\_rw\_noexattrfile
### Title: selinuxuser\_rw\_noexattrfile SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinuxuser\_share\_music
### Title: selinuxuser\_share\_music SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinuxuser\_tcp\_server
### Title: selinuxuser\_tcp\_server SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinuxuser\_udp\_server
### Title: selinuxuser\_udp\_server SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_selinuxuser\_use\_ssh\_chroot
### Title: selinuxuser\_use\_ssh\_chroot SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sge\_domain\_can\_network\_connect
### Title: sge\_domain\_can\_network\_connect SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sge\_use\_nfs
### Title: sge\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_smartmon\_3ware
### Title: smartmon\_3ware SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_smbd\_anon\_write
### Title: smbd\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_spamassassin\_can\_network
### Title: spamassassin\_can\_network SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_spamd\_enable\_home\_dirs
### Title: spamd\_enable\_home\_dirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_squid\_connect\_any
### Title: squid\_connect\_any SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_squid\_use\_tproxy
### Title: squid\_use\_tproxy SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ssh\_chroot\_rw\_homedirs
### Title: ssh\_chroot\_rw\_homedirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ssh\_keysign
### Title: ssh\_keysign SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ssh\_sysadm\_login
### Title: ssh\_sysadm\_login SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_staff\_exec\_content
### Title: staff\_exec\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_staff\_use\_svirt
### Title: staff\_use\_svirt SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_swift\_can\_network
### Title: swift\_can\_network SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sysadm\_exec\_content
### Title: sysadm\_exec\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_telepathy\_connect\_all\_ports
### Title: telepathy\_connect\_all\_ports SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_telepathy\_tcp\_connect\_generic\_network\_ports
### Title: telepathy\_tcp\_connect\_generic\_network\_ports SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_tftp\_anon\_write
### Title: tftp\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_tftp\_home\_dir
### Title: tftp\_home\_dir SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_tmpreaper\_use\_nfs
### Title: tmpreaper\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_tmpreaper\_use\_samba
### Title: tmpreaper\_use\_samba SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_tor\_bind\_all\_unreserved\_ports
### Title: tor\_bind\_all\_unreserved\_ports SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_tor\_can\_network\_relay
### Title: tor\_can\_network\_relay SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_unconfined\_chrome\_sandbox\_transition
### Title: unconfined\_chrome\_sandbox\_transition SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_unconfined\_login
### Title: unconfined\_login SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_unconfined\_mozilla\_plugin\_transition
### Title: unconfined\_mozilla\_plugin\_transition SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_unprivuser\_use\_svirt
### Title: unprivuser\_use\_svirt SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_use\_ecryptfs\_home\_dirs
### Title: use\_ecryptfs\_home\_dirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_use\_fusefs\_home\_dirs
### Title: use\_fusefs\_home\_dirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_use\_lpd\_server
### Title: use\_lpd\_server SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_use\_nfs\_home\_dirs
### Title: use\_nfs\_home\_dirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_use\_samba\_home\_dirs
### Title: use\_samba\_home\_dirs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_user\_exec\_content
### Title: user\_exec\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_varnishd\_connect\_any
### Title: varnishd\_connect\_any SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_read\_qemu\_ga\_data
### Title: virt\_read\_qemu\_ga\_data SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_rw\_qemu\_ga\_data
### Title: virt\_rw\_qemu\_ga\_data SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_sandbox\_use\_all\_caps
### Title: virt\_sandbox\_use\_all\_caps SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_sandbox\_use\_audit
### Title: virt\_sandbox\_use\_audit SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_sandbox\_use\_mknod
### Title: virt\_sandbox\_use\_mknod SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_sandbox\_use\_netlink
### Title: virt\_sandbox\_use\_netlink SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_sandbox\_use\_sys\_admin
### Title: virt\_sandbox\_use\_sys\_admin SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_transition\_userdomain
### Title: virt\_transition\_userdomain SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_use\_comm
### Title: virt\_use\_comm SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_use\_execmem
### Title: virt\_use\_execmem SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_use\_fusefs
### Title: virt\_use\_fusefs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_use\_nfs
### Title: virt\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_use\_rawip
### Title: virt\_use\_rawip SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_use\_samba
### Title: virt\_use\_samba SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_use\_sanlock
### Title: virt\_use\_sanlock SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_use\_usb
### Title: virt\_use\_usb SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_virt\_use\_xserver
### Title: virt\_use\_xserver SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_webadm\_manage\_user\_files
### Title: webadm\_manage\_user\_files SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_webadm\_read\_user\_files
### Title: webadm\_read\_user\_files SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_wine\_mmap\_zero\_ignore
### Title: wine\_mmap\_zero\_ignore SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xdm\_bind\_vnc\_tcp\_port
### Title: xdm\_bind\_vnc\_tcp\_port SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xdm\_exec\_bootloader
### Title: xdm\_exec\_bootloader SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xdm\_sysadm\_login
### Title: xdm\_sysadm\_login SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xdm\_write\_home
### Title: xdm\_write\_home SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xen\_use\_nfs
### Title: xen\_use\_nfs SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xend\_run\_blktap
### Title: xend\_run\_blktap SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xend\_run\_qemu
### Title: xend\_run\_qemu SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xguest\_connect\_network
### Title: xguest\_connect\_network SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xguest\_exec\_content
### Title: xguest\_exec\_content SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xguest\_mount\_media
### Title: xguest\_mount\_media SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xguest\_use\_bluetooth
### Title: xguest\_use\_bluetooth SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xserver\_clients\_write\_xshm
### Title: xserver\_clients\_write\_xshm SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xserver\_execmem
### Title: xserver\_execmem SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_xserver\_object\_manager
### Title: xserver\_object\_manager SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_zabbix\_can\_network
### Title: zabbix\_can\_network SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_zarafa\_setrlimit
### Title: zarafa\_setrlimit SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_zebra\_write\_config
### Title: zebra\_write\_config SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_zoneminder\_anon\_write
### Title: zoneminder\_anon\_write SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_zoneminder\_run\_sudo
### Title: zoneminder\_run\_sudo SELinux Boolean
### Description:

```
default - Default SELinux boolean setting.
on - SELinux boolean is enabled.
off - SELinux boolean is disabled.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_httpd\_loglevel
### Title: HTTPD Log Level
### Description:

```
The setting for LogLevel in /etc/httpd/conf/httpd.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_max\_keepalive\_requests
### Title: Maximum KeepAlive Requests for HTTPD
### Description:

```
The setting for MaxKeepAliveRequests in httpd.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_web\_login\_banner\_text
### Title: Web Login Banner Verbiage
### Description:

```
Enter an appropriate login banner for your organization. Please note that new lines must
be expressed by the '\n' character and special characters like parentheses and quotation marks must be escaped with '\\'.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_postfix\_inet\_interfaces
### Title: Postfix Network Interfaces
### Description:

```
The setting for inet_interfaces in /etc/postfix/main.cf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_postfix\_relayhost
### Title: Postfix relayhost
### Description:

```
Specify the host all outbound email should be routed into.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_postfix\_root\_mail\_alias
### Title: Postfix Root Mail Alias
### Description:

```
Specify an email address (string) for a root mail alias.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_multiple\_time\_servers
### Title: Vendor Approved Time Servers
### Description:

```
The list of vendor-approved time servers
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_time\_service\_set\_maxpoll
### Title: Maximum NTP or Chrony Poll
### Description:

```
The maximum NTP or Chrony poll interval number in seconds specified as a power of two.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_tftpd\_secure\_directory
### Title: TFTP server secure directory
### Description:

```
Specify the directory which is used by TFTP server as a root directory when running in secure mode.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_snmpd\_ro\_string
### Title: SNMP read-only community string
### Description:

```
Specify the SNMP community string used for read-only access.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_snmpd\_rw\_string
### Title: SNMP read-write community string
### Description:

```
Specify the SNMP community string used for read-write access.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_firewalld\_sshd\_zone
### Title: SSH enabled firewalld zone
### Description:

```
Specify firewalld zone to enable SSH service. This value is used only for remediation purposes.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sshd\_approved\_ciphers
### Title: SSH Approved ciphers by FIPS
### Description:

```
Specify the FIPS approved ciphers that are used for data integrity protection by the SSH server.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sshd\_approved\_macs
### Title: SSH Approved MACs by FIPS
### Description:

```
Specify the FIPS approved MACs (message authentication code) algorithms
	that are used for data integrity protection by the SSH server.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sshd\_idle\_timeout\_value
### Title: SSH session Idle time
### Description:

```
Specify duration of allowed idle time.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sshd\_listening\_port
### Title: SSH Server Listening Port
### Description:

```
Specify port the SSH server is listening.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sshd\_max\_auth\_tries\_value
### Title: SSH Max authentication attempts
### Description:

```
Specify the maximum number of authentication attempts per connection.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sshd\_required
### Title: SSH is required to be installed
### Description:

```
Specify if the Policy requires SSH to be installed. Used by SSH Rules
to determine if SSH should be uninstalled or configured.
A value of 0 means that the policy doesn't care if OpenSSH server is installed or not. If it is installed, scanner will check for it's configuration, if it's not installed, the check will pass.
A value of 1 indicates that OpenSSH server package is not required by the policy;
A value of 2 indicates that OpenSSH server package is required by the policy.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sshd\_strong\_kex
### Title: SSH Strong KEX by FIPS
### Description:

```
Specify the FIPS approved KEXs (Key Exchange Algorithms) algorithms
	that are used for methods in cryptography by which cryptographic keys are exchanged between two parties
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sshd\_max\_sessions
### Title: SSH Max Sessions Count
### Description:

```
Specify the maximum number of open sessions permitted.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sshd\_set\_keepalive
### Title: SSH Max Keep Alive Count
### Description:

```
Specify the maximum number of idle message counts before session is terminated.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_rekey\_limit\_size
### Title: SSH RekeyLimit - size
### Description:

```
Specify the size component of the rekey limit.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_rekey\_limit\_time
### Title: SSH RekeyLimit - size
### Description:

```
Specify the size component of the rekey limit.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sshd\_disable\_compression
### Title: SSH Compression Setting
### Description:

```
Specify the compression setting for SSH connections.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sshd\_priv\_separation
### Title: SSH Privilege Separation Setting
### Description:

```
Specify whether and how sshd separates privileges when handling incoming network connections.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sshd\_set\_login\_grace\_time
### Title: SSH LoginGraceTime setting
### Description:

```
Configure parameters for how long the servers stays connected before the user has successfully logged in
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sshd\_set\_maxstartups
### Title: SSH MaxStartups setting
### Description:

```
Configure parameters for maximum concurrent unauthenticated connections to the SSH daemon.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sssd\_certificate\_verification\_digest\_function
### Title: SSSD certificate\_verification option
### Description:

```
Value of the certificate_verification option in
the SSSD config.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sssd\_memcache\_timeout
### Title: SSSD memcache\_timeout option
### Description:

```
Value of the memcache_timeout option in the [nss] section
of SSSD config /etc/sssd/sssd.conf.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sssd\_ssh\_known\_hosts\_timeout
### Title: SSSD ssh\_known\_hosts\_timeout option
### Description:

```
Value of the ssh_known_hosts_timeout option in the [ssh] section
of SSSD configuration file /etc/sssd/sssd.conf.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sssd\_ldap\_tls\_ca\_dir
### Title: SSSD LDAP Backend Client CA Certificate Location
### Description:

```
Path of a directory that contains Certificate Authority certificates.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_audit\_failure\_mode
### Title: Audit failure mode
### Description:

```
This variable is the setting for the -f option in Audit configuration which sets the failure mode of audit.
This option lets you determine how you want the kernel to handle critical errors.
Possible values are: 0=silent, 1=printk, 2=panic.
If the value is set to "2", the system is configured to panic (shut down) in the event of an auditing failure.
If the value is set to "1", the system is configured to only send information to the kernel log regarding the failure.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_audispd\_disk\_full\_action
### Title: Action for audispd to take when disk is full
### Description:

```
The setting for disk_full_action in /etc/audisp/audisp-remote.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_audispd\_network\_failure\_action
### Title: Action for audispd to take when network fails
### Description:

```
The setting for network_failure_action in /etc/audisp/audisp-remote.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_audispd\_remote\_server
### Title: Remote server for audispd to send audit records
### Description:

```
The setting for remote_server in /etc/audisp/audisp-remote.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_action\_mail\_acct
### Title: Account for auditd to send email when actions occurs
### Description:

```
The setting for action_mail_acct in /etc/audit/auditd.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_admin\_space\_left\_action
### Title: Action for auditd to take when disk space is low
### Description:

```
The setting for admin_space_left_action in /etc/audit/auditd.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_admin\_space\_left\_percentage
### Title: The percentage remaining in disk space before prompting admin\_space\_left\_action
### Description:

```
The setting for admin_space_left as a percentage in /etc/audit/auditd.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_disk\_error\_action
### Title: Action for auditd to take when disk errors
### Description:

```
'The setting for disk_error_action in /etc/audit/auditd.conf, if multiple
values are allowed write them separated by pipes as in "syslog|single|halt",
for remediations the first value will be taken'
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_disk\_full\_action
### Title: Action for auditd to take when disk is full
### Description:

```
'The setting for disk_full_action in /etc/audit/auditd.conf, if multiple
values are allowed write them separated by pipes as in "syslog|single|halt",
for remediations the first value will be taken'
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_flush
### Title: Auditd priority for flushing data to disk
### Description:

```
The setting for flush in /etc/audit/auditd.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_freq
### Title: Number of Record to Retain Before Flushing to Disk
### Description:

```
The setting for freq in /etc/audit/auditd.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_max\_log\_file
### Title: Maximum audit log file size for auditd
### Description:

```
The setting for max_log_file in /etc/audit/auditd.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_max\_log\_file\_action
### Title: Action for auditd to take when log files reach their maximum size
### Description:

```
The setting for max_log_file_action in /etc/audit/auditd.conf. The following options are available:
ignore - audit daemon does nothing.
syslog - audit daemon will issue a warning to syslog.
suspend - audit daemon will stop writing records to the disk.
rotate - audit daemon will rotate logs in the same convention used by logrotate.
keep_logs - similar to rotate but prevents audit logs to be overwritten. May trigger space_left_action if volume is full.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_num\_logs
### Title: Number of log files for auditd to retain
### Description:

```
The setting for num_logs in /etc/audit/auditd.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_space\_left
### Title: Size remaining in disk space before prompting space\_left\_action
### Description:

```
The setting for space_left (MB) in /etc/audit/auditd.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_space\_left\_action
### Title: Action for auditd to take when disk space just starts to run low
### Description:

```
The setting for space_left_action in /etc/audit/auditd.conf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_auditd\_space\_left\_percentage
### Title: The percentage remaining in disk space before prompting space\_left\_action
### Description:

```
The setting for space_left as a percentage in /etc/audit/auditd.conf
```


# SEE ALSO
**usg**(8)

# COPYRIGHT
Copyright 2025 Canonical Limited. All rights reserved.

The implementation of DISA-STIG rules, CIS rules, profiles, scripts, and other assets are based on the ComplianceAsCode open source project (https://www.open-scap.org/security-policies/scap-security-guide).

ComplianceAsCode's license file can be found in the /usr/share/ubuntu-scap-security-guides/benchmarks directory.
