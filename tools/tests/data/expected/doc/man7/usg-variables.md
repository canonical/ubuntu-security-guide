% USG-VARIABLES(7) usg-benchmarks 24.04.5
% Eduardo Barretto <eduardo.barretto@canonical.com>
% 11 August 2025

# NAME
usg-variables - usg variables list and description

# LIST OF VARIABLES AND THEIR DESCRIPTIONS
# List of variables
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

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sudo\_logfile
### Title: Sudo - logfile value
### Description:

```
Specify the sudo logfile to use. The default value used here matches the example
location from CIS, which uses /var/log/sudo.log.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_sudo\_timestamp\_timeout
### Title: Sudo - timestamp\_timeout value
### Description:

```
Defines the number of minutes that can elapse before sudo will ask for a passwd again.
If set to a value less than 0 the user's time stamp will never expire. Defining 0 means always prompt for a 
password. The default timeout value is 5 minutes.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_cis\_banner\_text
### Title: CIS Login Banner Verbiage
### Description:

```
Enter an appropriate login banner for your organization according to the local policy.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_login\_banner\_text
### Title: Login Banner Verbiage
### Description:

```
Enter an appropriate login banner for your organization. Please note that new lines must
be expressed by the '\n' character and special characters like parentheses and quotation marks must be escaped with '\\'.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_remote\_login\_banner\_text
### Title: Remote Login Banner Verbiage
### Description:

```
Enter an appropriate login banner for your organization. Please note that new lines must
be expressed by the '\n' character and special characters like parentheses and quotation marks must be escaped with '\\'.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_ssh\_confirm\_text
### Title: SSH Login Confirmation Verbiage
### Description:

```
Enter an appropriate SSH Login Confirmation banner for your organization. Please note that new lines must
be expressed by the '\n' character and special characters like parentheses and quotation marks must be escaped with '\'.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_hashing\_algorithm
### Title: Password Hashing algorithm
### Description:

```
Specify the system default encryption algorithm for encrypting passwords.
Defines the value set as ENCRYPT_METHOD in /etc/login.defs.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_hashing\_algorithm\_pam
### Title: Password Hashing algorithm for pam\_unix.so
### Description:

```
Specify the system default encryption algorithm for encrypting passwords.
Defines the hashing algorithm to be used in pam_unix.so.
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

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_enforcing
### Title: enforcing
### Description:

```
Disallow a password that does not meet the criteria
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_lcredit
### Title: lcredit
### Description:

```
Minimum number of lower case in password
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_maxrepeat
### Title: maxrepeat
### Description:

```
Maximum Number of Consecutive Repeating Characters in a Password
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_password\_pam\_maxsequence
### Title: maxsequence
### Description:

```
Maximum Number of Consecutive Character Sequences in a Password
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
Specify the number of rounds for the system password encryption algorithm.
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
keep_existing_mode - Don't change existing modes of AppArmor profiles.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_journal\_upload\_server\_certificate\_file
### Title: Remote server SSL CA certificate in PEM format for systemd-journal-upload service
### Description:

```
The setting for ServerCertificateFile in the journal-upload config file.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_journal\_upload\_server\_key\_file
### Title: Remote server SSL key in PEM format for systemd-journal-upload service
### Description:

```
The setting for ServerKeyFile in the journal-upload config file.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_journal\_upload\_server\_trusted\_certificate\_file
### Title: Remote server SSL CA certificate for systemd-journal-upload service
### Description:

```
The setting for TrustedCertificateFile in the journal-upload config file.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_journal\_upload\_url
### Title: Remote server for systemd-journal-upload service
### Description:

```
The setting for URL in the journal-upload config file.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_rsyslog\_remote\_loghost\_address
### Title: Remote Log Server
### Description:

```
Specify an URI or IP address of a remote host where the log messages will be sent and stored.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_network\_filtering\_service
### Title: Network filtering service
### Description:

```
Network filtering service: iptables, nftables, firewalld or ufw
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

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv6\_conf\_all\_forwarding\_value
### Title: net.ipv6.conf.all.forwarding
### Description:

```
Toggle IPv6 Forwarding
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

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_net\_ipv4\_tcp\_syncookies\_value
### Title: net.ipv4.tcp\_syncookies
### Description:

```
Enable to turn on TCP SYN Cookie
Protection
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

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nftables\_master\_config\_file
### Title: Nftables Master configuration file
### Description:

```
The file which contains top level configuration for nftables service, and with which,
the service is started.
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_nftables\_table
### Title: Nftables Tables
### Description:

```
Tables in nftables hold chains. Each table only has one address family and only applies 
to packets of this family. Tables can have one of six families.
 
```

## Rule id: xccdf\_org.ssgproject.content\_value\_sysctl\_kernel\_yama\_ptrace\_scope\_value
### Title: kernel.yama.ptrace\_scope
### Description:

```
The setting yama.ptrace_scope restricts the ability of a process
to observe and control the execution of another process via ptrace.
See https://www.kernel.org/doc/Documentation/security/Yama.txt
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_postfix\_inet\_interfaces
### Title: Postfix Network Interfaces
### Description:

```
The setting for inet_interfaces in /etc/postfix/main.cf
```

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_multiple\_time\_pools
### Title: Vendor Approved Time pools
### Description:

```
The list of vendor-approved pool servers
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

## Rule id: xccdf\_org.ssgproject.content\_value\_var\_timesync\_service
### Title: Time synchronization service
### Description:

```
Time synchronization service: systemd-timesyncd or chronyd
```

## Rule id: xccdf\_org.ssgproject.content\_value\_ssh\_approved\_macs
### Title: SSH Approved MACs by FIPS
### Description:

```
Specify the FIPS approved MACs (message authentication code) algorithms
	hat are used for data integrity protection by the SSH client.
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

## Rule id: xccdf\_org.ssgproject.content\_value\_sshd\_strong\_macs
### Title: SSH Strong MACs by FIPS
### Description:

```
Specify the FIPS approved MACs (Message Authentication Code) algorithms
	that are used for data integrity protection by the SSH server.
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
