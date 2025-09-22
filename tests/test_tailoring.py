import pytest

from usg.models import TailoringFile, TailoringFileError


def test_tailoringfile_load(tmp_path):
    # Load minimal working tailoring file
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/usg-benchmarks/ubuntu2404_CIS_1"/>
  <Profile id="xccdf_org.ssgproject.content_profile_test">
    <select idref="xccdf_org.ssgproject.content_rule_test_rule" selected="true"/>
  </Profile>
</Tailoring>
"""
    tailoring_path = tmp_path / "tailoring.xml"
    tailoring_path.write_text(tailoring_xml, encoding="utf-8")
    tailoring = TailoringFile.from_file(tailoring_path)
    assert tailoring is not None
    assert tailoring.tailoring_file == tailoring_path
    assert tailoring.profile.profile_id == "xccdf_org.ssgproject.content_profile_test"
    assert (
        tailoring.profile.profile_legacy_id
        == "xccdf_org.ssgproject.content_profile_test"
    )
    assert tailoring.profile.benchmark_id == "ubuntu2404_CIS_1"
    assert tailoring.profile.tailoring_file == tailoring_path
    assert tailoring.benchmark_id == "ubuntu2404_CIS_1"


def test_tailoringfile_missing_file():
    with pytest.raises(TailoringFileError):
        TailoringFile.from_file("missing.xml")


def test_tailoringfile_invalid_type(tmp_path):
    tailoring_json = """{ "tailoring_data": {} }"""
    tailoring_path = tmp_path / "tailoring.json"
    tailoring_path.write_text(tailoring_json, encoding="utf-8")
    with pytest.raises(TailoringFileError):
        TailoringFile.from_file(tailoring_path)


def test_tailoringfile_parse_legacy_cis():
    # Load minimal working legacy tailoring file
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/ubuntu-scap-security-guides/1/benchmarks/ssg-ubuntu2404-xccdf.xml"/>
  <Profile id="xccdf_org.ssgproject.content_profile_cis_level1_server_test">
    <select idref="xccdf_org.ssgproject.content_rule_test_rule" selected="true"/>
  </Profile>
</Tailoring>
"""
    benchmark_id, profile_id = TailoringFile._parse_tailoring_scap(tailoring_xml)
    assert benchmark_id == "ubuntu2404_CIS_1"
    assert profile_id == "xccdf_org.ssgproject.content_profile_cis_level1_server_test"


def test_tailoringfile_parse_legacy_stig():
    # Load minimal working legacy tailoring file
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/ubuntu-scap-security-guides/2/benchmarks/ssg-ubuntu2404-xccdf.xml"/>
  <Profile id="xccdf_org.ssgproject.content_profile_stig_test">
    <select idref="xccdf_org.ssgproject.content_rule_test_rule" selected="true"/>
  </Profile>
</Tailoring>
"""
    benchmark_id, profile_id = TailoringFile._parse_tailoring_scap(tailoring_xml)
    assert benchmark_id == "ubuntu2404_STIG_2"
    assert profile_id == "xccdf_org.ssgproject.content_profile_stig_test"


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
  <Profile id="xccdf_org.ssgproject.content_profile_test">
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
  <Profile id="xccdf_org.ssgproject.content_profile_test"/>
</Tailoring>
"""
    with pytest.raises(TailoringFileError, match="Missing benchmark.href"):
        TailoringFile._parse_tailoring_scap(tailoring_xml)


def test_tailoringfile_parse_unsupported_legacy_profile_id():
    # Test that bad legacy profile id raises an error
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/ubuntu-scap-security-guides/2/benchmarks/ssg-ubuntu2404-xccdf.xml"/>
  <Profile id="xccdf_org.ssgproject.content_profile_unsupported_stig_test">
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
  <Profile id="xccdf_org.ssgproject.content_profile_test"/>
</Tailoring>
"""
    with pytest.raises(TailoringFileError, match="Unrecognized benchmark.href"):
        TailoringFile._parse_tailoring_scap(tailoring_xml)
