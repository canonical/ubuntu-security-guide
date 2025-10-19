# Ubuntu Security Guide
# Copyright (C) 2025 Canonical Ltd.
#
# SPDX-License-Identifier: GPL-3.0-only
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import pytest

from usg.models import TailoringFile, TailoringFileError


def test_tailoringfile_load(tmp_path):
    # Load minimal working tailoring file
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/usg-benchmarks/ubuntu2404_CIS_1"/>
  <Profile id="xccdf_org.ssgproject.content_profile_test" extends="xccdf_org.ssgproject.content_profile_cis_level1_server">
    <select idref="xccdf_org.ssgproject.content_rule_test_rule" selected="true"/>
  </Profile>
</Tailoring>
"""
    tailoring_path = tmp_path / "tailoring.xml"
    tailoring_path.write_text(tailoring_xml, encoding="utf-8")
    channel_id, profile_id, base_profile_id = TailoringFile.parse_tailoring_file(tailoring_path)
    assert channel_id == "ubuntu2404_CIS_1"
    assert profile_id == "test"
    assert base_profile_id == "cis_level1_server"

def test_tailoringfile_missing_file():
    with pytest.raises(TailoringFileError):
        TailoringFile.parse_tailoring_file("missing.xml")


def test_tailoringfile_invalid_type(tmp_path):
    tailoring_json = """{ "tailoring_data": {} }"""
    tailoring_path = tmp_path / "tailoring.json"
    tailoring_path.write_text(tailoring_json, encoding="utf-8")
    with pytest.raises(TailoringFileError):
        TailoringFile.parse_tailoring_file(tailoring_path)


def test_tailoringfile_parse_legacy_cis():
    # Load minimal working legacy tailoring file
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/ubuntu-scap-security-guides/1/benchmarks/ssg-ubuntu2404-xccdf.xml"/>
  <Profile id="xccdf_org.ssgproject.content_profile_cis_level1_server_test" extends="xccdf_org.ssgproject.content_profile_cis_level1_server">
      <select idref="xccdf_org.ssgproject.content_rule_test_rule" selected="true"/>
  </Profile>
</Tailoring>
"""
    channel_id, profile_id, base_profile_id = TailoringFile._parse_tailoring_scap(tailoring_xml)
    assert channel_id == "ubuntu2404_CIS_1"
    assert profile_id == "cis_level1_server_test"
    assert base_profile_id == "cis_level1_server"


def test_tailoringfile_parse_legacy_stig():
    # Load minimal working legacy tailoring file
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/ubuntu-scap-security-guides/2/benchmarks/ssg-ubuntu2404-xccdf.xml"/>
  <Profile id="xccdf_org.ssgproject.content_profile_stig_test" extends="xccdf_org.ssgproject.content_profile_stig">
    <select idref="xccdf_org.ssgproject.content_rule_test_rule" selected="true"/>
  </Profile>
</Tailoring>
"""
    channel_id, profile_id, base_profile_id = TailoringFile._parse_tailoring_scap(tailoring_xml)
    assert channel_id == "ubuntu2404_STIG_2"
    assert profile_id == "stig_test"
    assert base_profile_id == "stig"

def test_tailoringfile_parse_invalid_xml():
    # Test that invalid XML raises an error
    with pytest.raises(TailoringFileError, match="XML parser failed to parse"):
        TailoringFile._parse_tailoring_scap("""<badxml>""")


def test_tailoringfile_parse_invalid_root():
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<BadRoot xmlns="http://checklists.nist.gov/xccdf/1.2">
    <benchmark href="/usr/share/usg-benchmarks/ubuntu2404_CIS_1"/>
    <Profile id="xccdf_org.ssgproject.content_profile_test"/>
</BadRoot>
"""
    with pytest.raises(TailoringFileError, match="Root element of tailoring"):
        TailoringFile._parse_tailoring_scap(tailoring_xml)


def test_tailoringfile_parse_no_profile():
    # Test that no profile raises an error
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/usg-benchmarks/ubuntu2404_CIS_1"/>
</Tailoring>
"""
    with pytest.raises(TailoringFileError, match="doesn't contain a profile"):
        TailoringFile._parse_tailoring_scap(tailoring_xml)


def test_tailoringfile_parse_two_profiles():
    # Test that two profiles raises an error
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/usg-benchmarks/ubuntu2404_CIS_1"/>
  <Profile id="xccdf_org.ssgproject.content_profile_test"/>
  <Profile id="xccdf_org.ssgproject.content_profile_cis_test2"/>
</Tailoring>
"""
    with pytest.raises(TailoringFileError, match="Multiple profiles"):
        TailoringFile._parse_tailoring_scap(tailoring_xml)


def test_tailoringfile_parse_no_profile_id():
    # Test that no profile id raises an error
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/usg-benchmarks/ubuntu2404_CIS_1"/>
  <Profile/>
</Tailoring>
"""
    with pytest.raises(TailoringFileError, match="no profile id"):
        TailoringFile._parse_tailoring_scap(tailoring_xml)


def test_tailoringfile_parse_no_benchmark():
    # Test that no benchmark raises an error
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <Profile id="xccdf_org.ssgproject.content_profile_cis_level1_server_test" extends="xccdf_org.ssgproject.content_profile_cis_level1_server">
    <select idref="xccdf_org.ssgproject.content_rule_test_rule" selected="true"/>
  </Profile>
</Tailoring>
"""
    with pytest.raises(TailoringFileError, match="missing the 'benchmark'"):
        TailoringFile._parse_tailoring_scap(tailoring_xml)


def test_tailoringfile_parse_no_benchmark_id_or_href():
    # Test that no benchmark id or href raises an error
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark/>
  <Profile id="xccdf_org.ssgproject.content_profile_test" extends="xccdf_org.ssgproject.content_profile_cis_level1_server"/>
</Tailoring>
"""
    with pytest.raises(TailoringFileError, match="Missing benchmark.href"):
        TailoringFile._parse_tailoring_scap(tailoring_xml)


def test_tailoringfile_parse_unsupported_legacy_profile_id():
    # Test that bad legacy profile id raises an error
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/ubuntu-scap-security-guides/2/benchmarks/ssg-ubuntu2404-xccdf.xml"/>
  <Profile id="xccdf_org.ssgproject.content_profile_unsupported_stig_test" extends="xccdf_org.ssgproject.content_profile_stig">
    <select idref="xccdf_org.ssgproject.content_rule_test_rule" selected="true"/>
  </Profile>
</Tailoring>
"""
    with pytest.raises(
            TailoringFileError,
            match="Cannot infer benchmark type from profile"
            ):
        TailoringFile._parse_tailoring_scap(tailoring_xml)


def test_tailoringfile_parse_malformed_benchmark_href():
    # Test that malformed legacy benchmark href raises an error
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="missing.xml"/>
  <Profile id="xccdf_org.ssgproject.content_profile_test" extends="xccdf_org.ssgproject.content_profile_cis_level1_server"/>
</Tailoring>
"""
    with pytest.raises(TailoringFileError, match="Unrecognized benchmark.href"):
        TailoringFile._parse_tailoring_scap(tailoring_xml)
