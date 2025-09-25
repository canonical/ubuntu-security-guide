## Tools

The `tools/` folder contains several utility scripts for building benchmark data used by USG,
and deploying and testing USG in container environments.

### Build tooling

The build script `build.py` is used call the various tools to:
- compile [ComplianceAsCode content](https://github.com/ComplianceAsCode/content) based on tags defined in [](tools/release_metadata/)
- extract SCAP datastreams
- generate tailoring files and manpages from templates
- generate the necessary metadata files for USG
- populate `benchmarks/` and `docs/` folders

##### Example usage:

```
# install dependencies for building ComplianceAsCode
# install OpenSCAP
# install build dependencies
# (e.g. on Ubuntu 24.04)
sudo apt install openscap-scanner python3-yaml python3-lxml

# Obtain a copy of the CaC-content repo
git clone https://github.com/ComplianceAsCode/content /tmp/CaC-content

# Define benchmark release metadata in "tools/release_metadata" (see below)
vim tools/release_metadata/cis.yaml

# Run tool script
tools/build.py -c /tmp/CaC-content
```

##### Benchmark release metadata

The benchmark data is built based on the metadata defined in `tools/release_metadata/`.
This folder contains `*.yaml` files describing all benchmarks which should be considered for the build,
their git tags/commits in the ComplianceAsCode project, and their parent releases.

Annotated example:
```yaml
general:
  benchmark_type: CIS     # type, either CIS or STIG (each type has its own file)
  product: ubuntu2404
  product_long: Ubuntu 24.04 LTS (Noble Numbat)

benchmark_releases:
  - cac_tag: v0.1.78           # Git tag in ComplianceAsContent-content
    parent_tag: v0.1.77        # Tag of parent CaC release
    breaking_release: True     # Set to True if the release introduces backwards-incompatible changes to tailoring file
    tailoring_version: 2       # Version of tailoring file (must be incremented with every breaking release)
    cac_commit: f7d79485...    # Git commit corresponding to above tag
    usg_version: 24.04.5
    benchmark_data:            # Benchmark metadata (version, profiles, description, etc)
      version: v1.0.0
      profiles:
          cis_level1_server: {}
          cis_level2_server: {}
          cis_level1_workstation: {}
          cis_level2_workstation: {}
      description: |
          ComplianceAsCode implementation of CIS Ubuntu 24.04 LTS v1.0.0 benchmark.
      release_notes_url: https://github.com/canonical/ubuntu-security-guide/pull/72
      reference_url: https://www.cisecurity.org/benchmark/ubuntu_linux/

  - cac_tag: v0.1.77
    parent_tag:                # no parent tag, initial release
    breaking_release: False
    tailoring_version: 1
    ...
```

Based on this information, the build tools resolve the benchmark release graph, and build the active releases:
- the latest release
- all releases preceding a breaking release (deprecated versions)

Releases which are superseded by a compatible release (non-breaking; not introducing backwards incompatible changes to the tailoring file)
are not included in the build.

##### Build test data

Test data in `tools/data


### 

