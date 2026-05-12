"""Match installed apps against the Echap-style IOC index.

Emits one CRITICAL `Finding` per (app, IOC) hit, preferring package match over
cert match. French remediation: every CRITICAL finding embeds the 3919 (violences
faites aux femmes) and 17 (police-secours) helplines plus a `_SAFETY_FIRST_FR`
warning so survivors are not pushed to act before they're safe.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping

from ..models import (
    Finding,
    FindingKind,
    Helpline,
    InstalledApp,
    RemediationAdvice,
    Severity,
)
from ..signatures.loader import IOCIndex, SampleIOC

_SAFETY_FIRST_FR = (
    "Avant toute action de suppression, mettez-vous en sécurité : l'auteur des "
    "violences peut être alerté si l'application est retirée. Si vous êtes en "
    "danger immédiat, contactez le 17. Pour être accompagnée, appelez le 3919 "
    "(violences faites aux femmes, anonyme et gratuit)."
)

_HELP_FR_HIGH: list[Helpline] = [
    Helpline(
        name="Violences Femmes Info",
        phone="3919",
        url="https://arretonslesviolences.gouv.fr/",
        description="Numéro national d'écoute, anonyme et gratuit (24/7).",
    ),
    Helpline(
        name="Police-secours",
        phone="17",
        description="Urgence — danger immédiat.",
    ),
]


def _finding_id(package: str, matched_on: str, ioc_name: str) -> str:
    raw = f"signature_hit|{package}|{matched_on}|{ioc_name}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _build_finding(
    app: InstalledApp,
    ioc: SampleIOC,
    matched_on: str,
    cert_sha256: str | None,
) -> Finding:
    evidence: dict[str, object] = {
        "matched_on": matched_on,
        "ioc_name": ioc.name,
        "ioc_type": ioc.type,
        "ioc_source": ioc.source_path,
    }
    if cert_sha256:
        evidence["cert_sha256"] = cert_sha256
    if app.apk_path:
        evidence["apk_path"] = app.apk_path
    if app.installer_package:
        evidence["installer_package"] = app.installer_package

    summary = (
        f"Application correspondant à un stalkerware connu ({ioc.name}) "
        f"détectée : {app.label or app.package}"
    )
    details = (
        f"Le paquet « {app.package} » correspond à l'IOC « {ioc.name} » "
        f"({ioc.type}) via {matched_on}. Cette correspondance provient de la "
        f"base Echap/signatures embarquée."
    )

    remediation = RemediationAdvice(
        risk_summary=(
            "Un stalkerware peut lire vos messages, votre position et écouter "
            "votre micro à votre insu."
        ),
        safety_first=_SAFETY_FIRST_FR,
        steps=[
            "Ne supprimez rien tout de suite si vous craignez une réaction "
            "violente de l'auteur.",
            "Privilégiez un téléphone ou un ordinateur tiers (proche de "
            "confiance, médiathèque) pour appeler le 3919.",
            "Conservez les preuves (captures d'écran, rapport généré) pour "
            "un éventuel dépôt de plainte.",
            "Quand vous êtes en lieu sûr, désinstallez l'application puis "
            "réinitialisez le téléphone aux paramètres d'usine.",
        ],
        helplines=list(_HELP_FR_HIGH),
    )

    return Finding(
        id=_finding_id(app.package, matched_on, ioc.name),
        severity=Severity.CRITICAL,
        kind=FindingKind.SIGNATURE_HIT,
        target_package=app.package,
        target_label=app.label,
        summary=summary,
        details=details,
        evidence=evidence,
        remediation=remediation,
        references=list(ioc.references),
    )


def analyze(
    *,
    apps: Iterable[InstalledApp],
    certs_by_pkg: Mapping[str, str],
    index: IOCIndex,
) -> list[Finding]:
    """Return the list of CRITICAL findings for every app that hits the IOC index.

    Match priority per app: package first, then cert SHA-256. At most one finding
    per app is emitted (the first hit wins).
    """
    findings: list[Finding] = []
    for app in apps:
        ioc = index.match_package(app.package)
        if ioc is not None:
            findings.append(_build_finding(app, ioc, "package", None))
            continue

        cert = certs_by_pkg.get(app.package)
        if cert:
            ioc = index.match_cert(cert)
            if ioc is not None:
                findings.append(_build_finding(app, ioc, "cert", cert.lower()))
    return findings
