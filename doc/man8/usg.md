% USG(8) usg 1.0.0
% Richard Maciel Costa <richard.maciel.costa@canonical.com>, Nikos Mavrogiannopoulos <nikos.mavrogiannopoulos@canonical.com>
% September 2021

# NAME
usg - Audit and remediation tool for security benchmarks compliance automatization

# SYNOPSYS
**usg** *command* [*command_opts*] [*command_args*]

**usg** **audit** [**`--tailoring-file` filename** | **profile**]

**usg** **fix** [**`--tailoring-file` filename** | **profile**]

**usg** **generate-fix** [**`--output` filename**] [**`--tailoring-file` filename** | **profile**]

**usg** **generate-tailoring** **profile** **filename**

Available profiles: *cis_level1_server* | *cis_level2_server* | *cis_level1_workstation* | *cis_level2_workstation* | *stig*

# DESCRIPTION
**usg**, short for Ubuntu Security Guide, is a tool to audit and comply with security guides such as CIS and DISA-STIG.
The tool is designed to carry the basic operations needed to maintain and audit compliance on a system, while using the powerful OpenSCAP engine.

**usg** provides four commands, **audit**, **fix**, **generate-fix** and **generate-tailoring**, which are described in the **commands** section.

Running **usg** without any command line parameters cause **usg** to display its usage message.

# COMMANDS
**usg audit**
: Run the audit tests for the provided profile. That is, it checks if the profile is already applied on the system or not. The output is written to both an user-friendly HTML file and a file containing extensive report. See the *FILES* section for more information.

**usg fix**
: Run the audit tests for the given profile and remediate when the system doesn't meet the test. This command modifies the running system and **it requires a reboot after it finishes, to full apply the fixes!**. Use this command on a recently provisioned system or already installed applications may not function properly.

**usg generate-fix**
: Generates a Bash script containing commands to setup the system to comply with the profile or to the tailoring file provided.

**usg generate-tailoring**
: Generates a tailoring file based on the provided profile. This tailoring file serves many purposes. It allows to optimize the compliance of the system by filling the necessary variables, comply with a subset of the profile rules, as well as to fix to a specific profile version.

# OPTIONS
**`--help`**
: Displays the usage message

**`--output`**
: Filepath of the remediate file generated. Only works when the command is **generate-fix**.

**`--tailoring-file`**
: Sets the path to the tailoring-file, which contains a set of rules-selectors and value-customization elements, effectively letting the user customize the rules which will be applied. If that option is used, then the **profile** parameter is **ignored**! This option can be used for both commands. Check the **Tailoring Files** section for more info on them.

# EXAMPLES
1. audit system using DISA-STIG profile

    `# usg audit stig`

2. audit and remediate system using CIS Level 1 Server profile

    `# usg fix cis_level1_server`

3. generate tailoring file based on profile cis\_level2\_workstation

    `# usg generate-tailoring cis_level2_workstation /root/cis_level2_workstation-tailoring.xml`

4. generate fix script based on the previous tailoring file

    `# usg generate-fix --output /root/usg_fix_script.sh --tailoring-file /root/cis_level2_workstation-tailoring.xml`

5. generate a default tailoring file for the system based on cis\_level2\_workstation

    `# usg generate-tailoring cis_level2_workstation /etc/usg/default-tailoring.xml`

5. audit and remediate system using the default tailoring file for the system

    `# usg fix`


# TAILORING FILES
**usg** rules are associated with **usg profiles** (and their benchmark counterparts) on XCCDF files used by OpenSCAP, which also contain the parameters used by the rules.
The XCCDF files, however, are quite verbose and complicated and usg hides the complexity of dealing with them. **Tailoring files** is the way to customize profiles with usg.

A tailoring file is a XML file which contains the list of rules that are used in auditing and fixing with their corresponding parameters.

In practice it can be used to set specific parameters of the audit (e.g., valid groups which can access the machine through ssh, set on variable *var\_sshd\_allow\_users\_valid*, affecting rule *sshd\_configure\_allow\_users*), or customize a general profile to the organization's requirements.
The XML file is composed of *xccdf:select* and *xccdf:set-value* elements, described below.

## The xccdf:select element
This element sets if a given **usg rule** will be audited (and/or fixed, depending on the command/options used) or not. So, as an example, if the administrator wants to customize his tailoring file to disable the *sshd\_set\_loglevel\_info\_or\_verbose* rule execution, its associated *xccdf:select* element must be set as below:

```
<xccdf:select idref="sshd_set_loglevel_info_or_verbose" selected="false"/>
```

## the xccdf:set-value element
This element sets a variable associated with a given **usg rule**. The variable will change the way the rule executes in a specific way for that rule. So, as an example, if the administrator wants to customize his tailoring file to change the *var\_sshd\_set\_loglevel* variable to the value 'VERBOSE', its associated *xccdf:set-value* element must be set as below:

```
<xccdf:set-value idref="var_sshd_set_loglevel">VERBOSE</xccdf:set-value>
```

For a list of rules and their descriptions, see the **usg-rules** man page.  
For a list of variables and their descriptions, see the **usg-variables** man page.

## Tailoring files and Benchmark rules
The **usg-benchmark-\<VERSION\>** package provides 5 tailoring files in its *tailoring* subdirectory inside its installation directory, one for each profile. Those tailoring files are essentially a copy of their respective profiles, containing their respective rules, so an admin can can disable specific ones.

The provided tailoring files also group the *usg rules* according to the benchmark rules they belong to, with the comments pointing to the benchmark rule identifier and its name.

**We strongly recommend using the command generate-tailoring to get a copy of the tailoring file and customize that copy, instead of modifying the original ones**

Note that the *generate-tailoring* command uses the aforementioned original tailoring files to generate new ones.

# BENCHMARKS PACKAGES
The *usg* tool depends on one or more *usg-benchmarks-\<VERSION\>* packages to be able to execute its operations. The *usg* tool quits with an error message if it detects none.

## Benchmark package version
The \<VERSION\> suffix is used to provide information regarding changes to the benchmarks bundled into the Benchmarks package. So, the package starts with \<VERSION\> is initially
set to 1 and this value is increased each time a bundled benchmark receives an upgrade. For instance, the package version 1 contains CIS benchmark version 1.0.0 and DISA-STIG version
V1R1. Canonical may decide to update CIS benchmark to version 2.0.1, but keep DISA-STIG version V1R1, which will lead to an a new Benchmarks package version 2.
Note that the Benchmarks package version is not tied to the bundled benchmarks versions!

So, if both *usg-benchmarks-1* and *usg-benchmarks-2* packages are installed, the system will output the following lines when listing the packages:

```
$ dpkg -l 'usg-benchmarks*'
ii  usg-benchmarks-1 20.04.10 all          SCAP content for CIS and DISA-STIG Ubuntu Benchmarks
ii  usg-benchmarks-2 20.04.10 all          SCAP content for CIS and DISA-STIG Ubuntu Benchmarks
```

As one may see, the benefit of using this approach is to allow installation of more than one Benchmark package. Next section explains how to select a specific Benchmarks package version
after installation.

In case where **no** usg-benchmarks-\<VERSION\> packages are installed, then **usg** tool issues an error message when executing any of its commands.

## Benchmarks package selection
The usg-benchmarks-\<VERSION\> packages register themselves upon installation with the Debian alternatives system with the *usg_benchmarks* name. If both *usg-benchmarks-1* and
*usg-benchmarks-2* packages are installed, listing the Debian alternatives system will output the following lines:

```
$ update-alternatives --list usg_benchmarks
/usr/share/ubuntu-scap-security-guides/1
/usr/share/ubuntu-scap-security-guides/2
```

Also, the Debian alternatives system displays additional information regarding the current selected Benchmarks package:

```
$ update-alternatives --display usg_benchmarks
usg_benchmarks - auto mode
  link best version is /usr/share/ubuntu-scap-security-guides/1
  link currently points to /usr/share/ubuntu-scap-security-guides/1
  ...
```

In order the benchmarks from version 2, use the following command:

`sudo update-alternatives --config usg_benchmarks`

and set the number associated with version 2 on the selection menu.

For more information on how to use the *update-alternatives* command check the **update-alternatives** man page.

# TAILORING FILES AND BENCHMARKS VERSIONS
The *benchmark* element of a tailoring file has the attribute href which points to the base XCCDF files which the tailoring file is based upon. Take the
following snippet of a tailoring file as an example:

```
<cdf-11-tailoring:Tailoring xmlns:cdf-11-tailoring="http://open-scap.org/page/Xccdf-1.1-tailoring" xmlns:xccdf="http://checklists.nist.gov/xccdf/1.1" id="xccdf_scap-workbench_tailoring_default">
  <cdf-11-tailoring:benchmark href="/usr/share/ubuntu-scap-security-guides/1/benchmarks/Canonical_Ubuntu_20.04_Benchmarks-xccdf.xml"/>
  <cdf-11-tailoring:version time="2021-09-23T14:32:50">1</cdf-11-tailoring:version>
  <xccdf:Profile id="cis_level1_server_customized" extends="cis_level1_server">
```

That URL includes the specific version of the Benchmarks package (version 1 in this case).

That information is used by the *usg* tool to verify if the the tailoring file is compatible with the current Benchmarks package selected. This only occurs if they hold the same version.

In the above example the *benchmark* element has the version included in one of the components of the path, so the *usg* tool will only execute operations with that tailoring file
if *usg_benchmark* points to Benchmarks package version 1.

# FILES
/etc/usg/default-tailoring.xml

> When this file is present it is treated as the default tailoring file and is read automatically when no profile is given.

/var/lib/usg/usg-results-DATE.xml

> Result file generated by the audit process, containing extensive information on the rules tested and the outcome of each `usg rule` test.

/var/lib/usg/usg-report-DATE.html

> HTML file report containing the rules audited and their results in an user-friendly format.

# ADDITIONAL INFORMATION

## What are Security Technical Implementation Guides or Benchmarks?
Security Technical Implementation Guides (STIGs), sometimes called security benchmarks, are documents which contain sets of security-oriented rules created with the purpose of helping system administrators harden their systems.
The scope of the rules can be quite extensive and span both the operating system and all the software installed on it.

Benchmarks, like CIS, create sets of rules for specific environments (like server or workstation environments) and provide additional levels of security (CIS level 2 is safer, but has additional impact on the usability).

## Benchmark rules vs usg rules
This man page will refer as **benchmark rules** for the rules described in their specific benchmark documents. For instance, Canonical Ubuntu 20.04 CIS 1.0.0 rule 5.6, which is a rule defined in the document of the CIS benchmark for Ubuntu 20.04 version 1.0.0.
On the other hand, **usg rules** are sets of specific instructions, described in computer languages, used to audit and/or fix a system.  
A **benchmark rule is implemented by one or more usg rules**.

## What are Profiles?
Profiles are set of **usg rules** which, together, implement the rules described by a specific benchmark (CIS or STIG). For instance, the profile *cis_level1_server* states that the *usg rules* implement audit and remediation instructions to make a system as compliant as possible with the Ubuntu 20.04 CIS Benchmark, specifically, with its CIS level 1 server set of benchmark rules (which is also called a profile by the CIS).

Note that the DISA-STIG benchmark only has a single profile, because it's thought to run in a broad set of environments.

If you desire to customize the rules which are ran in a given profile or customize their parameters, use the **`--tailoring-file`** option to point **usg** to **Tailoring files**.

Note, however, that if the **tailoring-file** option is not provided, the user **must** provide a profile name for the **usg** tool!

See more info on **Tailoring Files** on the same-name section.

### Additional Info on Profiles
CIS Profiles (**cis_level1_server**, **cis_level2_server**, **cis_level1_workstation** and **cis_level2_workstation**)
: Level 1 profiles have smaller usability impact than their level 2 counterparts.
: Server profiles are made for Canonical Ubuntu Server images, while Workstation profiles are made for Workstation images, which generally implies the use of a graphical interface.

Profiles for DISA-STIG (**stig**)
: Sole profile for DISA-STIG provides the entire set of rules made for Canonical Ubuntu DISA-STIG benchmark.

For more info on CIS and DISA-STIG, look at the respective benchmark documents.

# INTERNET RESOURCES
OpenScap: https://www.open-scap.org/

Ubuntu 20.04 CIS Benchmark: https://workbench.cisecurity.org/benchmarks/5288

Ubuntu 20.04 STIG Benchmark: https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U\_CAN\_Ubuntu\_20-04\_LTS\_V1R1\_STIG.zip

# SEE ALSO
**usg-rules**(7), **usg-variables**(7), **usg-cis**(7), **usg-disa-stig**(7), **oscap**(8), **update-alternatives**(1)

# COPYRIGHT
Copyright 2021 Canonical Limited. All rights reserved.
