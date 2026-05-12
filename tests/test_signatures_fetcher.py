import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from stalkerware_detector.signatures import fetcher


def test_default_cache_dir_is_under_user_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert fetcher.default_cache_dir() == tmp_path / "stalkerware-detector" / "echap"


def test_is_fresh_false_when_no_meta(tmp_path):
    assert fetcher.is_fresh(tmp_path, ttl_seconds=86400) is False


def test_is_fresh_true_when_meta_recent(tmp_path):
    meta = {"fetched_at": time.time(), "commit": "abc"}
    (tmp_path / ".meta.json").write_text(json.dumps(meta))
    assert fetcher.is_fresh(tmp_path, ttl_seconds=86400) is True


def test_is_fresh_false_when_meta_stale(tmp_path):
    meta = {"fetched_at": time.time() - 90000, "commit": "abc"}
    (tmp_path / ".meta.json").write_text(json.dumps(meta))
    assert fetcher.is_fresh(tmp_path, ttl_seconds=86400) is False


def test_ensure_fresh_clones_when_missing(tmp_path):
    target = tmp_path / "echap"

    def fake_git(args, cwd=None):
        # Simulate `git clone` creating the target dir
        if args[0:2] == ["clone", fetcher.ECHAP_REPO_URL]:
            Path(args[2]).mkdir(parents=True, exist_ok=True)
            (Path(args[2]) / "README.md").write_text("echap")
            return "Cloning..."
        if args[0:3] == ["rev-parse", "HEAD"]:
            return "deadbeef\n"
        return ""

    with patch.object(fetcher, "_git", side_effect=fake_git):
        meta = fetcher.ensure_fresh(target, allow_network=True)
    assert (target / "README.md").exists()
    assert meta.commit == "deadbeef"


def test_ensure_fresh_skips_when_cache_is_fresh(tmp_path):
    target = tmp_path / "echap"
    target.mkdir()
    (target / ".meta.json").write_text(
        json.dumps({"fetched_at": time.time(), "commit": "stale-but-fresh"})
    )
    with patch.object(fetcher, "_git") as git:
        meta = fetcher.ensure_fresh(target, allow_network=True)
    git.assert_not_called()
    assert meta.commit == "stale-but-fresh"


def test_ensure_fresh_no_network_raises_when_no_cache(tmp_path):
    target = tmp_path / "echap"
    with pytest.raises(fetcher.SignatureCacheError):
        fetcher.ensure_fresh(target, allow_network=False)
