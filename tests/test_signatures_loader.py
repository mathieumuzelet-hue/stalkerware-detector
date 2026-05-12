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
