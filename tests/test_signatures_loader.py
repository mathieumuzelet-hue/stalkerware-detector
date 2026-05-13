from stalkerware_detector.signatures import loader


def test_load_index_from_dir_indexes_packages(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    assert "com.lsdroid.cerberus" in index.by_package
    assert "com.mspy.android" in index.by_package
    assert len(index.by_package) == 2


def test_load_index_indexes_certs_case_insensitive(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    # cert is uppercase in the YAML; queries should be lowercased
    assert "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" in index.by_cert


def test_load_index_indexes_apk_hashes(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    assert "1" * 64 in index.by_sha256
    assert "2" * 64 in index.by_sha256


def test_load_index_skips_broken_yaml_with_warning(fixtures_dir, caplog):
    index = loader.load_index(fixtures_dir / "echap_mini")
    assert "broken" not in {ioc.name for ioc in index.by_package.values()}
    assert any("broken.yaml" in rec.message for rec in caplog.records)


def test_match_package_returns_ioc(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    hit = index.match_package("com.lsdroid.cerberus")
    assert hit is not None
    assert hit.name == "cerberus"


def test_match_cert_is_case_insensitive(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    hit = index.match_cert("AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899")
    assert hit is not None
    assert hit.name == "cerberus"


def test_match_unknown_returns_none(fixtures_dir):
    index = loader.load_index(fixtures_dir / "echap_mini")
    assert index.match_package("com.unknown") is None


def test_load_index_parses_real_ioc_yaml(fixtures_dir):
    """Real Echap format: top-level YAML list with `packages` / `certificates`."""
    index = loader.load_index(fixtures_dir / "echap_real_mini")
    # Both entries' packages must show up
    assert "com.apspy.app" in index.by_package
    assert "com.thetruth" in index.by_package
    assert "com.lsdroid.cerberus" in index.by_package
    # IOC name comes from the top-level entry, not the file stem
    assert index.by_package["com.apspy.app"].name == "TheTruthSpy"
    assert index.by_package["com.lsdroid.cerberus"].name == "Cerberus"
    # references propagated
    assert "https://example.org/thetruthspy" in index.by_package["com.apspy.app"].references
    # sha256 indexed
    assert (
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        in index.by_sha256
    )


def test_load_index_real_format_certificates_are_lowercased(fixtures_dir):
    """SHA-1 cert hex in YAML is uppercase; lookup must be lowercased."""
    index = loader.load_index(fixtures_dir / "echap_real_mini")
    # uppercase from the YAML
    assert "31a6ececd97cf39bc4126b8745cd94a7c30bf81c" in index.by_cert
    assert "aabbccddeeff00112233445566778899aabbccdd" in index.by_cert
    # match_cert tolerates case
    hit = index.match_cert("31A6ECECD97CF39BC4126B8745CD94A7C30BF81C")
    assert hit is not None
    assert hit.name == "TheTruthSpy"
