## Overview

This document gives a brief technical overview of the contents of the ubuntu-security-guide repository,
including the USG python module, build tooling, debian maintainer scripts and other important files.

### USG

The USG tool has been rewritten in Python, but it maintains command-line interface (CLI) backward compatibility with the original Bash version.
See also https://github.com/canonical/ubuntu-security-guide/pull/76

The core functionality resides in src/usg/, which contains the Python module, the CLI wrapper, and a legacy fallback script.
```sh
src/
├── cli
│   └── usg                  # CLI wrapper script (installed to /sbin; calls usg.cli)
├── legacy 
│   └── usg                  # legacy Bash usg (fallback if python3 is not available)
└── usg
    ├── backends.py          # adapter classes for auditing/remediation
    ├── cli.py               # CLI entry point, CLI parsing, list/info implementations
    ├── config.py            # default config and loader functions
    ├── models.py            # data classes for benchmarks, profiles, tailoring files
    ├── results.py           # data classes for audit results
    ├── usg.py               # core module (used by CLI)
    ├── utils.py             # utility functions like gunzipping, permission checks, etc
    ├── constants.py
    ├── exceptions.py
    └── version.py
```
The implementation details are described in some more detail later.

### Project configuration

The project version, configuration and metadata is in `pyproject.toml`. On older platforms (Ubuntu <= 22.04),
`setup.cfg` is used due to lack of support for pyproject.toml in setuptools<61.0.

### Data directories

Data files packaged with USG, such as benchmarks, manpages, and configuration files, are located here:

```
benchmarks/                  # placeholder for benchmark data (see Build tooling)
doc/                         # placeholder for manpages (see Build tooling)
├── man7
├── man8
templates/                   # templates for building tailoring_files/docs
├── doc
└── tailoring
conf/                        # usg configuration files
├── logrotate.d 
└── usg.conf
```

### Tools

The `tools/` folder contains several utility scripts for building benchmark data used by USG, and deploying and testing USG in container environments.

#### Build tooling

The build script `build.py` is used call the various tools to:
- Compile [ComplianceAsCode content](https://github.com/ComplianceAsCode/content) based on tags defined in `tools/release_metadata/`.
- Extract SCAP datastreams.
- Generate tailoring files and manpages from templates.
- Generate the necessary metadata files for USG.
- Populate `benchmarks/` and `docs/` folders.

##### Example build

```
# Install dependencies for ComplianceAsCode and build tooling
# (Example for Ubuntu 24.04)
sudo apt install openscap-scanner cmake make python3-jinja2 ninja-build xsltproc libexpat1 python3-yaml python3-lxml

# Obtain a copy of the CaC-content repo
git clone https://github.com/ComplianceAsCode/content /tmp/CaC-content

# Define benchmark release metadata in "tools/release_metadata" (see below)
vim tools/release_metadata/cis.yaml

# Run tool script
tools/build.py -c /tmp/CaC-content
```

##### Benchmark release metadata

Benchmark data is built according to metadata defined in `*.yaml` files within `tools/release_metadata/`.
These files describe each benchmark, its corresponding Git tags/commits in the ComplianceAsCode project,
and its relationship to parent releases.

Here is an annotated example:
```yaml
general:
  benchmark_type: CIS     # type, either CIS or STIG (each type has its own file)
  product: ubuntu2404
  product_long: Ubuntu 24.04 LTS (Noble Numbat)

benchmark_releases:
  - cac_tag: v0.1.78           # Git tag in ComplianceAsContent-content
    parent_tag: v0.1.77        # Tag of parent CaC release
    release_channel: 2         # Benchmark release channel (must be incremented with every breaking release)
    cac_commit: f7d79485...    # Git commit corresponding to above tag
    usg_version: 24.04.5
    benchmark_data:            # Benchmark metadata (version, profiles, description, etc)
      version: v1.0.0
      profiles:
          cis_level1_server: {}
          cis_level2_server: {}
          cis_level1_workstation: {}
          cis_level2_workstation: {}
      description: |-
          ComplianceAsCode implementation of CIS Ubuntu 24.04 LTS v1.0.0 benchmark.
      release_notes_url: https://github.com/canonical/ubuntu-security-guide/pull/72
      reference_url: https://www.cisecurity.org/benchmark/ubuntu_linux/

  - cac_tag: v0.1.77
    parent_tag:                # no parent tag, initial release
    release_channel: 1
    ...
```

Based on this metadata, the build tools construct a release graph and build the latest releases in each channel as defined by the field `tailoring_version`.

Releases that are superseded by a non-breaking update (same `tailoring_version`) are not included in the final build.


#### Testing tools

For quick, live testing, you can use the provided container scripts:
```sh
# Install podman
sudo apt install podman

# Run a container for Ubuntu 24.04 (Noble) or 22.04 (Jammy)
./tools/run_container.sh noble
# or
./tools/run_container.sh jammy
```
The script will setup a Ubuntu 24.04 (noble) or Ubuntu 22.04 (jammy) container with USG and
sample benchmarks from test data.

You can then run commands like:
```sh
usg list --all
usg info cis_level1_server
usg audit cis_level1_server --debug
```

To execute the full suite of unit and end-to-end tests across all supported platforms, run:
```sh
sudo apt install podman
./tools/run_tests.sh
```

### Debian packaging

The debian packaging uses the pybuild backend, based on the metadata in `pyproject.toml` (or `setup.cfg` on Ubuntu 22.04 and older systems). 

Install locations:
- The `usg` python package is installed as a private package to `/usr/share/usg`.
- The USG CLI wrappper is installed to `/sbin/usg`.
- Benchmark data is installed to `/usr/share/usg-benchmarks`.

#### Autopkgtests

Autopkgtests scripts are stored in `debian/tests` and include a version check and E2E tests for the USG CLI.

#### Bash completions

Bash completions for usg CLI tool are in `debian/usg.bash-completion`.


## Development

To setup the dev environment (requires Python >= 3.12):
```
# Create virtual env and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r dev-requirements.txt

# Run tests with coverage report
coverage erase && coverage run --source . -m pytest && coverage html && coverage report -m

# Run the linter
ruff check .
```


## USG implementation details

#### High-level

The project consists of a Python library that can be imported and used programmatically:
```python
from usg import USG

# Initialize USG
# (requires that either the `usg-benchmarks` package is installed
# or benchmark data has been built using the build tooling as described above)
usg = USG(benchmark_metadata_path="benchmarks/benchmarks.json", state_dir=".")

# Get profile and run audit
profile = usg.get_profile("cis_level1_server-v1.0.0")
results, audit_artifacts = usg.audit(profile)

# Generate tailoring file
open("tailoring_file.xml", "w").write(usg.generate_tailoring(profile))

# Load tailoring file
tailoring_file = usg.load_tailoring("tailoring_file.xml")

# Audit using tailoring
results, audit_artifacts = usg.audit(tailoring_file.profile)
print(results.get_summary())

# Run fix only on rules which failed in audit
audit_results_file = audit_artifacts.get_by_type("audit_results").path
fix_artifacts = usg.fix(tailoring_file.profile, audit_results_file=audit_results_file)

```

and a CLI that uses this library:

```sh
usg list --all
usg info cis_level1_server
usg audit cis_level1_server
usg fix cis_level1_server --only-failed
```

#### Main components

##### USG

The central processing component in the code is the **usg.USG()** class which manages:
- **Benchmark metadata** - Loads `benchmarks.json` into `Benchmark` and `Profile` objects.
- **Tailoring files** - Loads tailoring files as `TailoringFile` and generates tailoring files via archive extraction.
- **Command routing** - Initializes environment, extracts backend files and routes commands (e.g. `audit`, `fix`, etc.) to a backend object such as `OpenscapBackend`.


##### Profile, Benchmarks, Tailoring files

The interface is built around the data component **Profile** (reason is primarily legacy support).
The Profile class contains metadata information about a profile and also references the
corresponding `Benchmark` and `TailoringFile` objects (if any).


##### Backend and Results

Functions like `audit` and `fix` take a **Profile** object, initialize a backend adapter (e.g., `OpenscapBackend`) in a secure temporary directory, and pass the necessary information to it. The adapter class handles the details of calling the `oscap` binary and parsing its output into an `AuditResults` object. All generated files (reports, logs) are returned via a `BackendArtifacts` object.


#### CLI

The CLI, implemented in `usg.cli` performs the following tasks:
- Parses CMDline arguments, ensuring backwards compatibility with legacy USG.
- Loads default configuration and overrides with `/etc/usg.conf` and CMDline args.
- Initializes logging to a log file defined in config.
- Initializes the main `usg.USG()` class.
- Routes subcommands (`audit`, `fix`, `generate-fix`, `generate-tailoring`) to USG
- Implements the `list` subcommand for listing available profiles
- Implements the `info` subcommand for printing information on a selected profile or tailoring file

