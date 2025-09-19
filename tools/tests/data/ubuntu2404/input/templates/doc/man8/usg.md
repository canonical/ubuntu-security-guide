% USG(8) usg <<USG_BENCHMARKS_VERSION_PLACEHOLDER>>
% Eduardo Barretto <eduardo.barretto@canonical.com>
% <<DATE_PLACEHOLDER>>

# NAME
usg - Audit and remediation tool for security benchmarks compliance automatization

# SYNOPSYS
**usg** *command* [*command_opts*] [*command_args*]

**usg** **list** [**`--all`**]

**usg** **info** [**`--tailoring-file` filename** | **profile**]

**usg** **audit** [**`--tailoring-file` filename** | **profile**]

**usg** **fix** [**`--tailoring-file` filename** | **profile**]

**usg** **generate-fix** [**`--output` filename**] [**`--tailoring-file` filename** | **profile**]

**usg** **generate-tailoring** **profile** **filename**

Available profiles: see **usg list**

# DESCRIPTION
**usg**, short for Ubuntu Security Guide, is a tool to audit and comply with security guides such as CIS and DISA-STIG.
The tool is designed to carry the basic operations needed to maintain and audit compliance on a system, while using the powerful OpenSCAP engine.

**usg** provides several commands, **list**, **info**, **audit**, **fix**, **generate-fix** and **generate-tailoring**, which are described in the **commands** section.

Running **usg** without any command line parameters cause **usg** to display its usage message.

# COMMANDS
**usg list**
: Lists available profiles. Only supported versions are shown by default. Use **--all** to list deprecated versions.

**usg info**
: Shows information about a specific profile or tailoring file.

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
1. list all profiles, including deprecated versions

    `# usg list --all`

2. show information about tailoring file **tailoring.xml**

    `# usg info -t tailoring.xml`

3. audit and remediate system using CIS Level 1 Server profile

    `# usg fix cis_level1_server`

4. generate tailoring file based on profile cis\_level2\_workstation

    `# usg generate-tailoring cis_level2_workstation /root/cis_level2_workstation-tailoring.xml`

5. generate fix script based on the previous tailoring file

    `# usg generate-fix --output /root/usg_fix_script.sh --tailoring-file /root/cis_level2_workstation-tailoring.xml`

6. generate a default tailoring file for the system based on cis\_level2\_workstation

    `# usg generate-tailoring cis_level2_workstation /etc/usg/default-tailoring.xml`

7. audit and remediate system using the default tailoring file for the system

    `# usg fix`


# TAILORING FILES
**usg** rules are associated with **usg profiles** (and their benchmark counterparts) on datastream files used by OpenSCAP, which also contain the parameters used by the rules.
The datastream files, however, are quite verbose and complicated and usg hides the complexity of dealing with them. **Tailoring files** is the way to customize profiles with usg.

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
The **usg-benchmarks** package provides tailoring files for each version of each profile in the *tailoring* subdirectory inside its installation directory.
Those tailoring files are essentially a copy of their respective profiles, containing their respective rules, so an admin can can disable specific ones.

The provided tailoring files also group the *usg rules* according to the benchmark rules they belong to, with the comments pointing to the benchmark rule identifier and its name.

**We strongly recommend using the command generate-tailoring to get a copy of the tailoring file and customize that copy, instead of modifying the original ones**

Note that the *generate-tailoring* command uses the aforementioned original tailoring files to generate new ones.

The *usg* tool depends on the *usg-benchmarks* package to be able to execute its operations. The *usg* tool quits with an error message if the package is missing.


# TAILORING FILES COMPATIBILITY
Tailoring files are tied to a major version of a profile and are incompatible with other versions.

The version is encoded in the *benchmark* element of a tailoring file in the attribute **href** and is used internally by the *usg* tool to map the tailoring file to a compatible datastream file.
Take the following snippet of a tailoring file as an example:

```
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_scap-workbench_tailoring_default">
  <benchmark href="/usr/share/usg-benchmarks/ubuntu2404_CIS_2"/>
  <version time="2025-08-07T13:34:47+00:00">1</version>
  <Profile id="xccdf_org.ssgproject.content_profile_cis_level1_server_customized" extends="xccdf_org.ssgproject.content_profile_cis_level1_server">
```

The above href attribute is comprised of target product (ubuntu2404), benchmark type (CIS), and the major profile version (2).

Note that the version is not related to the version of the upstream benchmark (e.g. STIG V1R3, CIS v2.0.0) but is used internally to differentiate
between backwards incompatible (major) releases of the profile. Such a release is made whenever rules are added, merged, split, or
contain significant modifications to the remediation, and would result in configuration changes that have not been evaluated by the end-user when
used with existing tailoring files (e.g. any added rules would be selected by default as they are not explicitly unselected in the tailoring file).

*Note*: The **href** attribute in older versions of tailoring files contains a URL to */usg/share/ubuntu-scap-security-guides* which *usg* internally remaps to the correct benchmark ID.

# FILES
/etc/usg.conf
  
  Main configuration file

/var/lib/usg/usg.log

> Default log file

/var/lib/usg/usg-results-DATE.xml

> Default result file generated by the audit process, containing extensive information on the rules tested and the outcome of each `usg rule` test.

/var/lib/usg/usg-report-DATE.html

> Default HTML file report containing the rules audited and their results in an user-friendly format.

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
CIS Profiles (**cis_level1_server**, **cis_level2_server**, **cis_level1_workstation**, **cis_level2_workstation**, **cis_level1_server_ec2)
: Level 1 profiles have smaller usability impact than their level 2 counterparts.
: Server profiles are made for Canonical Ubuntu Server images, while Workstation profiles are made for Workstation images, which generally implies the use of a graphical interface.

For more info on CIS, look at the respective benchmark documents.

# INTERNET RESOURCES
OpenScap: https://www.open-scap.org/

Ubuntu 24.04 CIS Benchmark v1.0.0: https://workbench.cisecurity.org/benchmarks/18959
.
# SEE ALSO
**usg-rules**(7), **usg-variables**(7), **usg-cis**(7), **usg-disa-stig**(7), **oscap**(8)

# COPYRIGHT
Copyright <<YEAR_PLACEHOLDER>> Canonical Limited. All rights reserved.
