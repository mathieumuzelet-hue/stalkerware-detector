"""Heuristic risk scoring on permission profiles + side-channel findings."""
from __future__ import annotations

import hashlib

from ..models import (
    Finding,
    FindingKind,
    GrantedPermission,
    Helpline,
    InstalledApp,
    RemediationAdvice,
    Severity,
)

SENSITIVE_PERMISSIONS: set[str] = {
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.SYSTEM_ALERT_WINDOW",
}

KNOWN_STORES: set[str] = {
    "com.android.vending",            # Play Store
    "com.sec.android.app.samsungapps",  # Galaxy Store
    "com.huawei.appmarket",
    "com.amazon.venezia",
    "org.fdroid.fdroid",
    "org.fdroid.fdroid.privileged",
}

_HELP_FR = [
    Helpline(
        name="3919 — Violences faites aux femmes",
        phone="3919",
        url="https://www.solidaritefemmes.org/",
    ),
    Helpline(name="17 — Police-secours", phone="17"),
]

_SAFETY_FIRST_FR = (
    "Avant de désinstaller : la disparition du logiciel peut alerter la personne "
    "qui l'a installé. Contacter le 3919 ou la police (17) si vous êtes en danger "
    "immédiat. Conserver ce rapport comme preuve."
)


def analyze(
    *,
    apps: list[InstalledApp],
    permissions: dict[str, list[GrantedPermission]],
    device_admins: list[str],
    accessibility: list[str],
    allowlist: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    da_set = set(device_admins)
    acc_set = set(accessibility)

    for app in apps:
        if app.system:
            continue

        # Side-channel: sideloaded (no installer, OR installer is not a known store).
        sideloaded = (
            app.installer_package is None
            or app.installer_package not in KNOWN_STORES
        )
        if sideloaded:
            findings.append(_sideloaded_finding(app))

        # Side-channel: device admin / accessibility
        if app.package in da_set:
            findings.append(_admin_finding(app, kind=FindingKind.DEVICE_ADMIN))
        if app.package in acc_set:
            findings.append(_admin_finding(app, kind=FindingKind.ACCESSIBILITY_SVC))

        # Permission profile (skip if allowlisted)
        if app.package in allowlist:
            continue
        granted = {p.name for p in permissions.get(app.package, []) if p.granted}
        score = len(granted & SENSITIVE_PERMISSIONS)
        if sideloaded:
            score *= 2
        privileged = app.package in da_set or app.package in acc_set

        if score == 0:
            continue
        severity: Severity | None = None
        if score >= 5 and privileged:
            severity = Severity.HIGH
        elif score >= 5:  # noqa: SIM114
            severity = Severity.MEDIUM
        elif score >= 3 and sideloaded:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        findings.append(_profile_finding(app, granted, score, severity, sideloaded, privileged))

    return findings


def _profile_finding(
    app: InstalledApp,
    granted: set[str],
    score: int,
    severity: Severity,
    sideloaded: bool,
    privileged: bool,
) -> Finding:
    fid = hashlib.sha1(f"permission_profile|{app.package}".encode()).hexdigest()[:16]
    matched = sorted(granted & SENSITIVE_PERMISSIONS)
    return Finding(
        id=fid,
        severity=severity,
        kind=FindingKind.PERMISSION_PROFILE,
        target_package=app.package,
        target_label=app.label,
        summary=f"Profil de permissions sensible ({len(matched)} permissions, score={score})",
        details=(
            f"L'application **{app.package}** dispose des permissions sensibles "
            f"suivantes : " + ", ".join(p.rsplit('.', 1)[-1] for p in matched) + ". "
            f"Score brut={len(matched)}, score ajusté={score}, "
            f"sideload={sideloaded}, privilège système actif={privileged}."
        ),
        evidence={
            "matched_permissions": matched,
            "raw_score": len(matched),
            "adjusted_score": score,
            "sideloaded": sideloaded,
            "privileged": privileged,
            "installer_package": app.installer_package,
        },
        remediation=_advice(severity),
    )


def _sideloaded_finding(app: InstalledApp) -> Finding:
    fid = hashlib.sha1(f"sideloaded|{app.package}".encode()).hexdigest()[:16]
    return Finding(
        id=fid,
        severity=Severity.LOW,
        kind=FindingKind.SIDELOADED_APP,
        target_package=app.package,
        summary="Application installée hors store officiel",
        details=(
            f"L'application **{app.package}** n'a pas été installée depuis un store "
            "connu (Play Store, Galaxy Store, F-Droid, etc.). Cela ne signifie pas "
            "qu'elle est malveillante, mais à vérifier."
        ),
        evidence={"installer_package": app.installer_package},
        remediation=RemediationAdvice(
            risk_summary="Provenance inconnue de l'application.",
            steps=["Vérifier l'origine de l'application avec son propriétaire."],
        ),
    )


def _admin_finding(app: InstalledApp, *, kind: FindingKind) -> Finding:
    label = (
        "administrateur de l'appareil"
        if kind is FindingKind.DEVICE_ADMIN
        else "service d'accessibilité"
    )
    fid = hashlib.sha1(f"{kind.value}|{app.package}".encode()).hexdigest()[:16]
    return Finding(
        id=fid,
        severity=Severity.HIGH,
        kind=kind,
        target_package=app.package,
        summary=f"L'application est active comme {label}",
        details=(
            f"**{app.package}** dispose actuellement du privilège de {label}, ce "
            "qui lui permet de lire l'écran, simuler des actions, ou empêcher sa "
            "propre désinstallation. Si vous n'avez pas activé ce privilège "
            "vous-même, c'est un signal très fort."
        ),
        evidence={"privilege": kind.value},
        remediation=_advice(Severity.HIGH),
    )


def _advice(severity: Severity) -> RemediationAdvice:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return RemediationAdvice(
            risk_summary=(
                "Cette application peut accéder à des données très sensibles "
                "(micro, localisation, SMS, contacts) à votre insu."
            ),
            safety_first=_SAFETY_FIRST_FR,
            steps=[
                "Mettre ce rapport en sécurité avant toute action visible.",
                "Si privilège administrateur actif : Paramètres > Sécurité > Administrateurs.",
                "Si service d'accessibilité actif : Paramètres > Accessibilité > Services.",
                "Désinstaller depuis Paramètres > Applications.",
                "Changer les mots de passe sensibles depuis un autre appareil.",
            ],
            helplines=list(_HELP_FR),
        )
    return RemediationAdvice(
        risk_summary="Profil de permissions à examiner.",
        steps=[
            "Ouvrir Paramètres > Applications > <l'app> > Permissions.",
            "Retirer les permissions sensibles non justifiées.",
        ],
    )
