#!/usr/bin/python3
#
# Ubuntu Security Guide
# Copyright (C) 2022 Canonical Limited
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import datetime
import configparser
import os
import re
import subprocess
import sys
import traceback

# This is assumed to be in the same directory as this script.
tools_directory = os.path.dirname(os.path.realpath(__file__))
configfile = "%s/build_config.ini" % (tools_directory)


def exit_error(msg):
    print(f"Build script exiting with error:\n{msg}\n")
    traceback.print_exc()
    sys.exit(1)


def load_config():
    config = configparser.ConfigParser()
    if config.read(configfile) == []:
        exit_error("Could not open config.ini file.\n"
                   "Is this present in the same directory as the script?")

    try:
        package_version = config["DEFAULT"]["version"]
    except KeyError:
        exit_error("\"version\" key is not present in a \"DEFAULT\" section.\n"
                   "Has config.ini been malformed?")

    try:
        alternative_version = config["DEFAULT"]["alternative_version"]
    except KeyError:
        exit_error("\"alternate_version\" key is not present in a \"DEFAULT\""
                   "section.\nHas config.ini been malformed?")

    try:
        target = config["DEFAULT"]["target"]
    except KeyError:
        exit_error("\"target\" key is not present in a \"DEFAULT\" section.\n"
                   "Has config.ini been malformed?")

    try:
        usg_directory = config["DEFAULT"]["usg_directory"]
    except KeyError:
        exit_error("\"usg_directory\" key is not present in a \"DEFAULT\""
                   "section.\nHas config.ini been malformed?")

    try:
        cac_directory = config["DEFAULT"]["cac_directory"]
    except KeyError:
        exit_error("\"cac_directory\" key is not present in a \"DEFAULT\""
                   "section.\nHas config.ini been malformed?")

    return package_version, alternative_version, target, usg_directory, cac_directory


def run_ppb(tools_directory, cac_directory, usg_directory):
    try:
        ppb_out = subprocess.check_output(
            ["%s/pre_package_build.sh" % (tools_directory),
             "%s/%s" % (tools_directory, cac_directory),
             "%s/%s" % (tools_directory, usg_directory)])
    except subprocess.CalledProcessError:
        exit_error("pre_package_build.sh returned a non-zero status."
                   "Possible failure.\n%s" % (ppb_out))


def update_alternative_version(usg_path, altver):
    try:
        control_file = open("%s/%s/debian/control" %
                            (tools_directory, usg_path), "r")
    except FileNotFoundError:
        exit_error("debian/control file was unable to be opened for reading.\n"
                   "Is \"usg_directory\" key in config.ini wrong?")
    control_data = control_file.read()
    control_file.close()

    try:
        control_file = open("%s/%s/debian/control" %
                            (tools_directory, usg_path), "w")
    except FileNotFoundError:
        exit_error("debian/control file was unable to be opened for writing.\n"
                   "Is \"usg_directory\" key in config.ini wrong?")

    control_data_corrected = re.sub(
        "Package: usg-benchmarks-*.$",
        "Package: usg-benchmarks-%s" % (altver),
        control_data,
        flags=re.MULTILINE)
    control_file.write(control_data_corrected)
    control_file.close()


def gen_documentation(cac_directory, usg_directory):
    # I'm opting to listen to the other module's outputs
    # rather than rebuilding the module.
    # This way the other module can still be used as it
    # was originally designed.

    doc_gen_command = ["rules", "variables"]
    doc_output = [""] * len(doc_gen_command)
    for i in range(len(doc_gen_command)):
        try:
            exec_arg_1 = "%s/create_rule_and_variable_doc.py" % \
                (tools_directory)
            exec_arg_2 = doc_gen_command[i]
            exec_arg_3 = "%s/%s/products/ubuntu2004/profiles" % \
                (tools_directory, cac_directory)
            exec_arg_4 =\
                "%s/%s/benchmarks/Canonical_Ubuntu_20.04_Benchmarks-xccdf.xml"\
                % (tools_directory, usg_directory)
            doc_output[i] = subprocess.check_output([
                sys.executable, exec_arg_1, exec_arg_2,
                exec_arg_3, exec_arg_4]).decode()
        except subprocess.CalledProcessError:
            exit_error("Executing `%s %s %s %s %s` failed." %
                       (sys.executable, exec_arg_1, exec_arg_2,
                        exec_arg_3, exec_arg_4))

    # In order of [rules, variables]
    return (doc_output[0], doc_output[1])

def gen_tailoring(cac_directory, usg_directory):

    # This is an array of profile paths (below cac_directory) in the order of c1s, c1w, c2s, c2w, stig
    tailoring_file_info = [
        "products/ubuntu2004/profiles/cis_level1_server.profile",
        "products/ubuntu2004/profiles/cis_level1_workstation.profile",
        "products/ubuntu2004/profiles/cis_level2_server.profile",
        "products/ubuntu2004/profiles/cis_level2_workstation.profile",
        "products/ubuntu2004/profiles/stig.profile"]

    gen_tailoring_script = "%s/generate_tailoring_file.py" % (tools_directory)
    benchmark_xml = \
        "%s/%s/benchmarks/Canonical_Ubuntu_20.04_Benchmarks-xccdf.xml" % \
        (tools_directory, usg_directory)
    tailoring_data = [""] * len(tailoring_file_info)

    for i in range(len(tailoring_file_info)):
        try:
            exec_arg_1 = gen_tailoring_script
            exec_arg_2 = "%s/%s/%s" % \
                (tools_directory, cac_directory, tailoring_file_info[i])
            exec_arg_3 = benchmark_xml
            tailoring_data[i] = subprocess.check_output([sys.executable, exec_arg_1, exec_arg_2, exec_arg_3]).decode()
        except:
            exit_error("\
                Executing `%s %s %s %s` failed."%(sys.executable, exec_arg_1, exec_arg_2, exec_arg_3))
    
    c1s_data = tailoring_data[0]
    c1w_data = tailoring_data[1]
    c2s_data = tailoring_data[2]
    c2w_data = tailoring_data[3]
    stig_data = tailoring_data[4]
    return (c1s_data, c1w_data, c2s_data, c2w_data, stig_data)

def mass_replacer(the_meat, meat_placeholder, package_version, alternative_version, current_timestamp, file_lines):
    # This function significantly reduces code reuse and other potential ickyness.
    # "the_meat" refers to the main data that needs to be put in the file,
    #   ie the generated documentation or tailoring XML data.
    # "meat_placeholder" is the template placeholder string for "the_meat"

    # Generate the different time-related values that this function will use.
    current_iso = current_timestamp.isoformat()
    current_datestring = datetime.datetime.strftime(current_timestamp, "%d %B %Y")
    current_year = current_timestamp.year

    corrected_lines = file_lines.replace(
        "<<YEAR_PLACEHOLDER>>", str(current_year))\
        .replace("<<DATE_PLACEHOLDER>>", str(current_datestring))\
        .replace("<<ISODATETIME_PLACEHOLDER>>", str(current_iso))\
        .replace("<<USG_BENCHMARKS_VERSION_PLACEHOLDER>>", str(package_version))\
        .replace("<<USG_BENCHMARKS_ALTERNATIVE_PLACEHOLDER>>", str(alternative_version))\
        .replace(meat_placeholder, str(the_meat))

    return corrected_lines

def build_files(rules_doc, vars_doc, c1s_data, c1w_data, c2s_data, c2w_data, stig_data, package_version, alternative_version, current_timestamp, usg_directory):
    # An array of [path, data, placeholder]
    data_info = [
        ["doc/man8/usg.md", "", "<<DOESNT_EXIST>>"],
        ["doc/man7/usg-cis.md", "", "<<DOESNT_EXIST>>"],
        ["doc/man7/usg-disa-stig.md", "", "<<DOESNT_EXIST>>"],
        ["doc/man7/usg-rules.md", rules_doc, "<<USG_MAN_RULES_PLACEHOLDER>>"],
        ["doc/man7/usg-variables.md", vars_doc, "<<USG_MAN_VARIABLE_PLACEHOLDER>>"],
        ["tailoring/cis_level1_server-tailoring.xml", c1s_data, "<<LEVEL_1_SERVER_TAILORING_PLACEHOLDER>>"],
        ["tailoring/cis_level1_workstation-tailoring.xml", c1w_data, "<<LEVEL_1_WORKSTATION_TAILORING_PLACEHOLDER>>"],
        ["tailoring/cis_level2_server-tailoring.xml", c2s_data, "<<LEVEL_2_SERVER_TAILORING_PLACEHOLDER>>"],
        ["tailoring/cis_level2_workstation-tailoring.xml", c2w_data, "<<LEVEL_2_WORKSTATION_TAILORING_PLACEHOLDER>>"],
        ["tailoring/stig-tailoring.xml", stig_data, "<<STIG_TAILORING_PLACEHOLDER>>"]]

    for specific_file_data in data_info:
        try:
            template_file = open("%s/%s/templates/%s" %
                                 (tools_directory, usg_directory,
                                  specific_file_data[0]), "r")
        except FileNotFoundError:
            exit_error("Template file at %s/%s/templates/%s cannot be opened."
                       % (tools_directory, usg_directory,
                          specific_file_data[0]))
        try:
            built_file = open("%s/%s/%s" %
                              (tools_directory, usg_directory,
                               specific_file_data[0]), "w")
        except FileNotFoundError:
            exit_error("File at %s/%s/%s cannot be opened for writing." %
                       (tools_directory, usg_directory, specific_file_data[0]))

        template_data = template_file.read()
        built_data = mass_replacer(specific_file_data[1], specific_file_data[2], package_version, alternative_version, current_timestamp, template_data)
        built_file.write(built_data)
        built_file.close()
        template_file.close()


def main(arg):
    # Get the current timestamp
    current_timestamp = datetime.datetime.utcnow().replace(microsecond=0)

    # Read configuration variables from config.ini
    package_version, alternative_version, target, usg_directory, cac_directory = load_config()

    # Run `pre_package_build.sh`
    run_ppb(tools_directory, cac_directory, usg_directory)

    # Update the alternative version number in debian/control
    update_alternative_version(usg_directory, alternative_version)

    # Generate the rules and variables documentation meat
    rules_doc, vars_doc = gen_documentation(cac_directory, usg_directory)

    # Generate the tailoring data
    c1s_data, c1w_data, c2s_data, c2w_data, stig_data = gen_tailoring(cac_directory, usg_directory)

    # Build the template files from all of the data that we've collected.
    build_files(rules_doc,\
                vars_doc,\
                c1s_data,\
                c1w_data,\
                c2s_data,\
                c2w_data,\
                stig_data,\
                package_version,\
                alternative_version,\
                current_timestamp,\
                usg_directory)


if __name__ == "__main__":
    main(sys.argv)
