import json

import pytest


@pytest.fixture(scope="session")
def dummy_benchmarks(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("dummy_benchmarks")
    # Create a dummy benchmarks.json file
    json_file = tmp_path / "benchmarks.json"
    json_data = {
        "version": 1,
        "benchmarks": [
            {
                "backend": "openscap",
                "benchmark_type": "CIS",
                "product": "ubuntu2404",
                "product_long": "Ubuntu 24.04 LTS (Noble Numbat)",
                "version": "v1.0.0",
                "profiles": {
                    "cis_level1_server": {},
                    "cis_level2_server": {},
                    "cis_level1_workstation": {},
                    "cis_level2_workstation": {},
                },
                "description": "ComplianceAsCode implementation of CIS Ubuntu 24.04 LTS v1.0.0 benchmark.\n",
                "release_notes_url": "https://github.com/canonical/ubuntu-security-guide/",
                "reference_url": "https://www.cisecurity.org/benchmark/ubuntu_linux/",
                "benchmark_id": "ubuntu2404_CIS_1",
                "compatible_versions": [],
                "breaking_upgrade_path": ["v1.0.1", "v2.0.0"],
                "is_latest": False,
                "data_files": {
                    "datastream_gz": {
                        "path": "ubuntu2404_CIS_1/ssg-ubuntu2404-ds.xml.gz",
                        "sha256": "5ef3b9feb87381e7cca99f50cfaae6d5789ba66e512e97bd82e027f2005a8366",
                    }
                },
                "tailoring_files": {
                    "cis_level1_server": {
                        "file": "ubuntu2404_CIS_1/tailoring/cis_level1_server-tailoring.xml",
                        "sha256": "b42b764d5b821a1e9089c2d9d373aeb4aa621107a184cc3da393ca7116607bd9",
                    },
                    "cis_level2_server": {
                        "file": "ubuntu2404_CIS_1/tailoring/cis_level2_server-tailoring.xml",
                        "sha256": "b1c953719606572f8ab507e9bfbbd570724127e8c87055aca90ebff85817e6f5",
                    },
                    "cis_level1_workstation": {
                        "file": "ubuntu2404_CIS_1/tailoring/cis_level1_workstation-tailoring.xml",
                        "sha256": "eed3ec7fd76fc4d23b218e72d007c5c94383fb754c7c2d76c8d54818c04be702",
                    },
                    "cis_level2_workstation": {
                        "file": "ubuntu2404_CIS_1/tailoring/cis_level2_workstation-tailoring.xml",
                        "sha256": "68f6300400bc99f8bb41d1db1f4d1e12399f86e5db0b11d7d8d712108e51d149",
                    },
                },
            },
            {
                "backend": "openscap",
                "benchmark_type": "CIS",
                "product": "ubuntu2404",
                "product_long": "Ubuntu 24.04 LTS (Noble Numbat)",
                "version": "v1.0.1",
                "profiles": {
                    "cis_level1_server": {},
                    "cis_level2_server": {},
                    "cis_level1_workstation": {},
                    "cis_level2_workstation": {},
                },
                "description": "ComplianceAsCode implementation of CIS Ubuntu 24.04 LTS v1.0.1 benchmark.\n",
                "benchmark_id": "ubuntu2404_CIS_2",
                "release_notes_url": "https://github.com/canonical/ubuntu-security-guide/",
                "reference_url": "https://www.cisecurity.org/benchmark/ubuntu_linux/",
                "compatible_versions": ["v1.0.0.usg1"],
                "breaking_upgrade_path": ["v2.0.0"],
                "is_latest": False,
                "data_files": {
                    "datastream_gz": {
                        "path": "ubuntu2404_CIS_2/ssg-ubuntu2404-ds.xml.gz",
                        "sha256": "5ef3b9feb87381e7cca99f50cfaae6d5789ba66e512e97bd82e027f2005a8366",
                    }
                },
                "tailoring_files": {
                    "cis_level1_server": {
                        "file": "ubuntu2404_CIS_2/tailoring/cis_level1_server-tailoring.xml",
                        "sha256": "b42b764d5b821a1e9089c2d9d373aeb4aa621107a184cc3da393ca7116607bd9",
                    },
                    "cis_level2_server": {
                        "file": "ubuntu2404_CIS_2/tailoring/cis_level2_server-tailoring.xml",
                        "sha256": "b1c953719606572f8ab507e9bfbbd570724127e8c87055aca90ebff85817e6f5",
                    },
                    "cis_level1_workstation": {
                        "file": "ubuntu2404_CIS_2/tailoring/cis_level1_workstation-tailoring.xml",
                        "sha256": "eed3ec7fd76fc4d23b218e72d007c5c94383fb754c7c2d76c8d54818c04be702",
                    },
                    "cis_level2_workstation": {
                        "file": "ubuntu2404_CIS_2/tailoring/cis_level2_workstation-tailoring.xml",
                        "sha256": "68f6300400bc99f8bb41d1db1f4d1e12399f86e5db0b11d7d8d712108e51d149",
                    },
                },
            },
            {
                "backend": "openscap",
                "benchmark_type": "CIS",
                "product": "ubuntu2404",
                "product_long": "Ubuntu 24.04 LTS (Noble Numbat)",
                "version": "v2.0.0",
                "profiles": {
                    "cis_level1_server": {},
                    "cis_level2_server": {},
                    "cis_level1_workstation": {},
                    "cis_level2_workstation": {},
                },
                "description": "ComplianceAsCode implementation of CIS Ubuntu 24.04 LTS v2.0.0 benchmark.\n",
                "release_notes_url": "https://github.com/canonical/ubuntu-security-guide/",
                "reference_url": "https://www.cisecurity.org/benchmark/ubuntu_linux/",
                "benchmark_id": "ubuntu2404_CIS_3",
                "compatible_versions": [],
                "breaking_upgrade_path": [],
                "is_latest": True,
                "data_files": {
                    "datastream_gz": {
                        "path": "ubuntu2404_CIS_3/ssg-ubuntu2404-ds.xml.gz",
                        "sha256": "5ef3b9feb87381e7cca99f50cfaae6d5789ba66e512e97bd82e027f2005a8366",
                    }
                },
                "tailoring_files": {
                    "cis_level1_server": {
                        "file": "ubuntu2404_CIS_3/tailoring/cis_level1_server-tailoring.xml",
                        "sha256": "b42b764d5b821a1e9089c2d9d373aeb4aa621107a184cc3da393ca7116607bd9",
                    },
                    "cis_level2_server": {
                        "file": "ubuntu2404_CIS_3/tailoring/cis_level2_server-tailoring.xml",
                        "sha256": "b1c953719606572f8ab507e9bfbbd570724127e8c87055aca90ebff85817e6f5",
                    },
                    "cis_level1_workstation": {
                        "file": "ubuntu2404_CIS_3/tailoring/cis_level1_workstation-tailoring.xml",
                        "sha256": "eed3ec7fd76fc4d23b218e72d007c5c94383fb754c7c2d76c8d54818c04be702",
                    },
                    "cis_level2_workstation": {
                        "file": "ubuntu2404_CIS_3/tailoring/cis_level2_workstation-tailoring.xml",
                        "sha256": "68f6300400bc99f8bb41d1db1f4d1e12399f86e5db0b11d7d8d712108e51d149",
                    },
                },
            },
            {
                "backend": "openscap",
                "benchmark_type": "STIG",
                "product": "ubuntu2404",
                "product_long": "Ubuntu 24.04 LTS (Noble Numbat)",
                "version": "V1R1",
                "profiles": {"stig": {"legacy_id": "disa_stig"}},
                "description": "ComplianceAsCode implementation of STIG Ubuntu 24.04 LTS V1R1 benchmark.\n",
                "release_notes_url": "https://github.com/canonical/ubuntu-security-guide/",
                "reference_url": "https://public.cyber.mil/stigs/downloads/",
                "benchmark_id": "ubuntu2404_STIG_1",
                "compatible_versions": [],
                "breaking_upgrade_path": ["V1R3"],
                "is_latest": False,
                "data_files": {
                    "datastream_gz": {
                        "path": "ubuntu2404_STIG_1/ssg-ubuntu2404-ds.xml.gz",
                        "sha256": "5ef3b9feb87381e7cca99f50cfaae6d5789ba66e512e97bd82e027f2005a8366",
                    }
                },
                "tailoring_files": {
                    "stig": {
                        "file": "ubuntu2404_STIG_1/tailoring/stig-tailoring.xml",
                        "sha256": "b42b764d5b821a1e9089c2d9d373aeb4aa621107a184cc3da393ca7116607bd9",
                    }
                },
            },
            {
                "backend": "openscap",
                "benchmark_type": "STIG",
                "product": "ubuntu2404",
                "product_long": "Ubuntu 24.04 LTS (Noble Numbat)",
                "version": "V1R3",
                "profiles": {"stig": {"legacy_id": "disa_stig"}},
                "description": "ComplianceAsCode implementation of STIG Ubuntu 24.04 LTS V1R3 benchmark.\n",
                "release_notes_url": "https://github.com/canonical/ubuntu-security-guide/",
                "reference_url": "https://public.cyber.mil/stigs/downloads/",
                "benchmark_id": "ubuntu2404_STIG_2",
                "compatible_versions": ["V1R2"],
                "breaking_upgrade_path": [],
                "is_latest": True,
                "data_files": {
                    "datastream_gz": {
                        "path": "ubuntu2404_STIG_2/ssg-ubuntu2404-ds.xml.gz",
                        "sha256": "5ef3b9feb87381e7cca99f50cfaae6d5789ba66e512e97bd82e027f2005a8366",
                    }
                },
                "tailoring_files": {
                    "stig": {
                        "file": "ubuntu2404_STIG_2/tailoring/stig-tailoring.xml",
                        "sha256": "b42b764d5b821a1e9089c2d9d373aeb4aa621107a184cc3da393ca7116607bd9",
                    }
                },
            },
        ],
    }

    json_file.write_text(json.dumps(json_data))
    return json_file
