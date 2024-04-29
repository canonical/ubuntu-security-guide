# Ubuntu Security Guide

This repository contains the Ubuntu Security Guide (usg) tool for Ubuntu Focal and later LTS releases.

Ubuntu Security Guide is a tool that makes hardening and auditing with compliance profiles easy on Ubuntu systems.
USG uses [OpenSCAP](https://github.com/OpenSCAP/openscap) as a backend.

### Reporting issues

Any issues found on usg should be reported on Launchpad:
https://bugs.launchpad.net/usg

Please don't forget to add some information such as:
1. usg version
2. Ubuntu version
3. Run the failling command with ``--debug`` and upload the logs.
4. Any other relevant information

### How to Build

No SCAP content is provided in this repository, but scripts are available in the `tools/` directory that assists with copying the SCAP content into place.
This SCAP content should be previously downloaded or generated using a tool, such as the [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content) tool.
Please review the instructions in `README.build` for information on how to use these scripts to prepare Ubuntu Security Guide.

### Previous Contributors

Prior to open sourcing these scripts on GitHub, these additional authors provided contributions:
- [Alexander Scheel](https://github.com/cipherboy)
- [Richard Maciel Costa](https://github.com/richardmaciel-canonical)
- [Nikos Mavrogiannopoulos](https://github.com/nmav)

