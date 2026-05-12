"""Match installed apps against the Echap IOC index (package + cert phase)."""
from __future__ import annotations

import hashlib

from ..models import Finding, FindingKind, Helpline, InstalledApp, RemediationAdvice, Severity
from ..signatures.loader import IOCIndex, SampleIOC

_HELP_FR_HIGH = [
    Helpline(
        name="3919 — Violences faites aux femmes",
        phone="3919",
        url="https://www.solidaritefemmes.org/",
        description="Gratuit, anonyme, 24/7.",
    ),
    Helpline(
        name="17 — Police-secours",
        phone="17",
        description="En cas de danger immédiat.",
    ),
]

_SAFETY_FIRST_FR = (
    "Avant de désinstaller : la disparition du logiciel peut alerter la personne "
    "qui l'a installé. Contacter le 3919 (gratuit, anonyme) ou la police (17) si "
    "vous êtes en danger immédiat. Conserver ce rapport comme preuve."
)


def analyze(
    *,
    apps: list[InstalledApp],
    certs_by_pkg: dict[str, list[str]],
    index: IOCIndex,
) -> list[Finding]:
    """Return findings for apps matching a known stalkerware IOC."""
    findings: list[Finding] = []
    for app in apps:
        ioc = index.match_package(app.package)
        matched_on = "package"
        matched_value: str = app.package

        if ioc is None:
            for cert in certs_by_pkg.get(app.package, []):
                hit = index.match_cert(cert)
                if hit is not None:
                    ioc = hit
                    matched_on = "cert"
                    matched_value = cert
                    break

        if ioc is None:
            continue

        findings.append(_build_finding(app, ioc, matched_on, matched_value))
    return findings


def _build_finding(
    app: InstalledApp, ioc: SampleIOC, matched_on: str, matched_value: str
) -> Finding:
    fid = hashlib.sha1(
        f"signature_hit|{app.package}|{matched_on}|{ioc.name}".encode()
    ).hexdigest()[:16]
    return Finding(
        id=fid,
        severity=Severity.CRITICAL,
        kind=FindingKind.SIGNATURE_HIT,
        target_package=app.package,
        target_label=app.label,
        summary=f"Stalkerware connu détecté : {ioc.name}",
        details=(
            f"Le package **{app.package}** correspond à une signature connue de "
            f"stalkerware (**{ioc.name}**) référencée dans la base "
            f"AssoEchap/stalkerware-indicators. Correspondance trouvée par "
            f"**{matched_on}**."
        ),
        evidence={
            "matched_on": matched_on,
            "matched_value": matched_value,
            "ioc_name": ioc.name,
            "ioc_type": ioc.type,
            "source_path": ioc.source_path,
        },
        remediation=RemediationAdvice(
            risk_summary=(
                "Ce type de logiciel peut accéder à la localisation, aux SMS, "
                "aux appels, au micro et à la caméra à l'insu de l'utilisatrice."
            ),
            safety_first=_SAFETY_FIRST_FR,
            steps=[
                "Mettre ce rapport en sécurité (impression, transfert sur un autre "
                "appareil de confiance).",
                "Contacter une association d'aide (3919) avant toute action visible.",
                "Désinstaller via Paramètres > Applications > <l'app> > Désinstaller.",
                "Si l'app dispose des droits administrateur, les retirer d'abord dans "
                "Paramètres > Sécurité > Administrateurs de l'appareil.",
                "Changer les mots de passe importants depuis un autre appareil sain.",
                "Envisager une réinitialisation d'usine après extraction des données.",
            ],
            helplines=list(_HELP_FR_HIGH),
        ),
        references=list(ioc.references),
    )
