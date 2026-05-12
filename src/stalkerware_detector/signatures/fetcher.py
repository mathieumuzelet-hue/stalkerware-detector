"""Fetch and cache the AssoEchap/stalkerware-indicators repository.

Strategy: a plain `git clone` into a cache dir, then `git pull` if the cache TTL
expired. We store a small `.meta.json` next to the repo for quick freshness
checks without invoking git.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

ECHAP_REPO_URL = "https://github.com/AssoEchap/stalkerware-indicators.git"
DEFAULT_TTL_SECONDS = 24 * 60 * 60


class SignatureCacheError(RuntimeError):
    pass


@dataclass(frozen=True)
class IndexMeta:
    fetched_at: float
    commit: str


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "stalkerware-detector" / "echap"
    return Path.home() / ".cache" / "stalkerware-detector" / "echap"


def is_fresh(target: Path, *, ttl_seconds: int) -> bool:
    meta_path = target / ".meta.json"
    if not meta_path.exists():
        return False
    try:
        meta = json.loads(meta_path.read_text())
    except json.JSONDecodeError:
        return False
    fetched_at = float(meta.get("fetched_at", 0))
    return (time.time() - fetched_at) < ttl_seconds


def ensure_fresh(
    target: Path,
    *,
    allow_network: bool = True,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    force: bool = False,
) -> IndexMeta:
    """Make sure `target` contains an up-to-date clone of the Echap repo.

    - If the cache is fresh (or force=False and TTL not expired) and the dir
      exists, do nothing and return the cached meta.
    - Otherwise clone (if missing) or `git pull` (if present).
    - If `allow_network=False` and no cache, raise SignatureCacheError.
    """
    cache_exists = target.exists() and any(target.iterdir())

    if cache_exists and not force and is_fresh(target, ttl_seconds=ttl_seconds):
        return _read_meta(target)

    if not allow_network:
        if not cache_exists:
            raise SignatureCacheError(
                f"No cached signature index at {target} and --no-network was set."
            )
        return _read_meta(target)

    if not cache_exists:
        target.parent.mkdir(parents=True, exist_ok=True)
        _git(["clone", ECHAP_REPO_URL, str(target)])
    else:
        _git(["pull", "--ff-only"], cwd=str(target))

    commit = _git(["rev-parse", "HEAD"], cwd=str(target)).strip()
    meta = IndexMeta(fetched_at=time.time(), commit=commit)
    _write_meta(target, meta)
    return meta


def _read_meta(target: Path) -> IndexMeta:
    meta_path = target / ".meta.json"
    if not meta_path.exists():
        return IndexMeta(fetched_at=0.0, commit="unknown")
    data = json.loads(meta_path.read_text())
    return IndexMeta(
        fetched_at=float(data["fetched_at"]),
        commit=str(data.get("commit", "unknown")),
    )


def _write_meta(target: Path, meta: IndexMeta) -> None:
    (target / ".meta.json").write_text(
        json.dumps({"fetched_at": meta.fetched_at, "commit": meta.commit})
    )


def _git(args: list[str], *, cwd: str | None = None) -> str:
    cmd = ["git", *args]
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SignatureCacheError(
            f"git {' '.join(args)} failed: {result.stderr.strip()}"
        )
    return result.stdout
