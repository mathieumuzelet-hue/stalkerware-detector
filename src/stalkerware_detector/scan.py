"""Top-level scan orchestration: pulled out of cli.py so it stays unit-testable."""
from __future__ import annotations

from . import __version__
from .analyzers import signature_match
from .collectors import cert as cert_collector
from .collectors import packages
from .device import adb, session
from .models import DeviceInfo, InstalledApp, ScanReport, SignatureIndexMeta
from .signatures import fetcher, loader

_DEFAULT_SAFETY = (
    "Avant de désinstaller quoi que ce soit : la disparition du stalkerware peut "
    "alerter la personne qui l'a installé. Contactez d'abord le 3919 ou la police "
    "(17) en danger immédiat. Conservez ce rapport comme preuve."
)


def run_scan(*, serial: str | None, allow_network: bool, interactive: bool) -> ScanReport:
    sess = session.connect(requested_serial=serial, interactive=interactive)

    cache_dir = fetcher.default_cache_dir()
    sig_meta = fetcher.ensure_fresh(cache_dir, allow_network=allow_network)
    index = loader.load_index(cache_dir)

    apps = packages.collect(sess.serial)
    certs_by_pkg = _collect_certs(sess.serial, apps)

    findings = signature_match.analyze(apps=apps, certs_by_pkg=certs_by_pkg, index=index)

    return ScanReport(
        tool_version=__version__,
        device=DeviceInfo(
            serial_redacted=session.redact_serial(sess.serial),
            manufacturer=sess.info.manufacturer,
            model=sess.info.model,
            android_release=sess.info.android_release,
            sdk_int=sess.info.sdk_int,
            build_id=sess.info.build_id,
            security_patch=sess.info.security_patch,
        ),
        signature_index=SignatureIndexMeta(
            commit=sig_meta.commit, fetched_at=sig_meta.fetched_at,
        ),
        findings=findings,
        safety_warning=_DEFAULT_SAFETY,
    )


def _collect_certs(serial: str, apps: list[InstalledApp]) -> dict[str, list[str]]:
    """For non-system apps, extract cert SHA-256 from dumpsys."""
    out: dict[str, list[str]] = {}
    for app in apps:
        if app.system:
            continue
        try:
            dump = adb.run_shell(serial, f"dumpsys package {app.package}")
        except adb.AdbError:
            continue
        cert_hash = cert_collector.extract_cert_sha256(dump)
        if cert_hash:
            out[app.package] = [cert_hash]
    return out
