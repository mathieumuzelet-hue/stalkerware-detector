# Android Stalkerware Detector — Design Spec

**Date** : 2026-05-12
**Auteur** : Mathieu Muzelet (avec Claude Opus 4.7)
**Statut** : Brouillon — en attente validation utilisateur
**Repo cible** : `github.com/mathieumuzelet-hue/stalkerware-detector`

---

## 1. Contexte & objectif

Outil en ligne de commande qui scanne un téléphone Android branché en USB et détecte
la présence de stalkerware (logiciels d'espionnage installés à l'insu de la victime,
typiquement dans le cadre de violences conjugales ou de harcèlement).

L'outil cible un public mixte : un journaliste, un membre d'association d'aide aux
victimes, ou une personne technicienne qui aide un proche. Le rapport produit doit
être compréhensible par une victime non-technique.

**Outils existants comparables** :

- **MVT (Mobile Verification Toolkit, Amnesty International)** — forensics complet,
  pas orienté stalkerware-only, sortie technique.
- **TinyCheck (Kaspersky)** — basé sur la capture du trafic réseau, pas sur le scan
  device via ADB.
- **Coalition Against Stalkerware / Echap** — fournit la base de signatures
  référence (`github.com/AssoEchap/stalkerware-indicators`) mais pas de scanner.

Notre outil se positionne sur le créneau **scan device via ADB + UX victime-friendly**.

## 2. Périmètre

**Inclus dans la v1** :

- Détection par signatures (base Echap, fetch live + cache 24 h).
- Analyse heuristique des permissions et des privilèges sensibles
  (device admin, accessibility services).
- Trois sorties : terminal coloré, JSON, HTML self-contained.
- Conseils de remédiation contextuels (FR) + liens vers ressources d'aide.

**Explicitement hors scope v1** :

- Capture de trafic réseau (couvert par TinyCheck).
- Scan iOS (couvert par MVT-iOS).
- Analyse de logs / backup `.ab` (forensics profond).
- Interface graphique (CLI uniquement).
- Détection des CA certificates installés manuellement.
- Désinstallation automatisée des stalkerware (éthique : la victime décide).

## 3. Choix techniques

| Décision | Choix | Raison |
|---|---|---|
| Langage | Python 3.11+ | Standard du domaine (MVT, TinyCheck), riche écosystème |
| CLI framework | Typer | Annotations Python natives, ergonomique |
| HTTP/Git | `requests` + `git` CLI | Fetch repo Echap |
| Rendu console | `rich` | Tables, panels, couleurs |
| HTML | `Jinja2` + CSS inline | Self-contained, zéro JS externe |
| Modèles | `Pydantic v2` | Validation, sérialisation JSON, versionning schema |
| Tests | `pytest` + fixtures dumps réels | Pas de mock subprocess |
| Packaging | Poetry | Lock fichier, build wheel |
| Licence | GPL-3.0 | Cohérent avec écosystème stalkerware (Echap, MVT) |
| ADB | Pré-requis utilisateur, non bundlé | Évite bloat de 60 MB + désync sécurité |
| Profondeur détection | Signatures + permissions (pas full forensic) | Couvre 90 % des cas, exécution rapide |
| Source signatures | Echap live, cache 24 h | Base maintenue par la Coalition Against Stalkerware |

## 4. Architecture

### 4.1 Arborescence du repo

```
stalkerware-detector/
├─ pyproject.toml
├─ README.md
├─ LICENSE                                  # GPL-3.0
├─ src/stalkerware_detector/
│  ├─ __init__.py
│  ├─ cli.py                                # Typer : scan / update-sigs / doctor / version
│  ├─ device/
│  │  ├─ adb.py                             # Wrapper subprocess autour de `adb`
│  │  └─ session.py                         # DeviceSession : sélection device, capture info OS
│  ├─ collectors/
│  │  ├─ packages.py                        # `pm list packages -f -U -i`
│  │  ├─ permissions.py                     # `dumpsys package <pkg>`
│  │  ├─ device_admin.py                    # `dumpsys device_policy`
│  │  └─ accessibility.py                   # `dumpsys accessibility` + `settings get secure ...`
│  ├─ signatures/
│  │  ├─ fetcher.py                         # Clone / pull github.com/AssoEchap/stalkerware-indicators
│  │  ├─ loader.py                          # Parse YAML stix2 -> IOC index
│  │  ├─ legitimate_apps.yaml               # Allowlist publique, committée
│  │  └─ cache/                             # gitignored, ~/.cache/stalkerware-detector/
│  ├─ analyzers/
│  │  ├─ signature_match.py                 # Packages installés ∩ signatures Echap
│  │  └─ permission_risk.py                 # Heuristique scoring permissions
│  ├─ remediation/
│  │  └─ advisor.py                         # Conseils contextuels FR par type de finding
│  ├─ reporters/
│  │  ├─ console.py                         # rich
│  │  ├─ json_report.py                     # Schema versionné
│  │  └─ html_report.py                     # Jinja2 + template self-contained
│  ├─ models.py                             # Pydantic : Finding, Severity, App, ScanReport
│  └─ templates/
│     └─ report.html.j2                     # CSS inline, zéro JS externe
├─ tests/
│  ├─ fixtures/                             # Dumps adb réels anonymisés
│  ├─ test_collectors.py
│  ├─ test_signature_match.py
│  ├─ test_permission_risk.py
│  └─ test_reporters.py
└─ docs/superpowers/specs/
   └─ 2026-05-12-android-stalkerware-detector-design.md   # ce fichier
```

**Principes** :

- `device/adb.py` est la seule frontière qui appelle réellement
  `subprocess.run(["adb", ...])`. Tout le reste prend du texte/JSON en entrée et
  est testable sans téléphone.
- `signatures/` isolé de la logique de scan — testable sans réseau avec des
  fixtures YAML locales.
- `remediation/advisor.py` porte la valeur métier "victime-friendly".

### 4.2 Pipeline d'un scan

```
1. cli.py scan
      ↓
2. DeviceSession.connect()
   - `adb devices` ; si 0 device, exit 11
   - si > 1 device, prompt user ou flag --serial
   - capture : serial, model, android_version, build_id, security_patch
      ↓
3. SignatureIndex = SignatureLoader.load()
   - SignatureFetcher.ensure_fresh() : clone ou git pull si cache > 24 h
   - parse tous les YAML stix2 -> dict { package_name, sha256, cert_sha256 -> IOC }
      ↓
4. Collectors EN SÉQUENCE (adb ne supporte pas le parallélisme)
   - packages.collect(session)             -> list[InstalledApp]
   - permissions.collect(session, apps)    -> dict[package, list[GrantedPermission]]
   - device_admin.collect(session)         -> list[package] (device admins actifs)
   - accessibility.collect(session)        -> list[package] (accessibility services actifs)
      ↓
5. Analyzers (peuvent tourner en parallèle, indépendants)
   - SignatureMatcher.analyze(apps, index)         -> list[Finding]
   - PermissionRiskScorer.analyze(apps, perms, ...) -> list[Finding]
      ↓
6. ScanReport (Pydantic)
   - meta : timestamp, tool_version, device_info, signature_index_version
   - findings triés par severity desc
   - summary : counts par severity
   - safety_warning toujours en tête si findings >= HIGH
      ↓
7. Reporters
   - ConsoleReporter.render(report)
   - JsonReporter.write(report, path)
   - HtmlReporter.write(report, path)
```

### 4.3 Modèles (extraits)

```python
class Severity(StrEnum):
    CRITICAL = "critical"   # match direct signature stalkerware connu
    HIGH     = "high"       # combo permissions très intrusif + app non-store
    MEDIUM   = "medium"     # permissions sensibles isolées
    LOW      = "low"        # signal faible, info seulement
    INFO     = "info"

class FindingKind(StrEnum):
    SIGNATURE_HIT       = "signature_hit"
    PERMISSION_PROFILE  = "permission_profile"
    DEVICE_ADMIN        = "device_admin"
    ACCESSIBILITY_SVC   = "accessibility_service"
    SIDELOADED_APP      = "sideloaded_app"

class InstalledApp(BaseModel):
    package: str
    label: str | None
    version_name: str | None
    version_code: int | None
    apk_path: str
    installer_package: str | None
    first_install_time: datetime | None
    last_update_time: datetime | None
    system: bool
    enabled: bool

class RemediationAdvice(BaseModel):
    risk_summary: str
    safety_first: str        # toujours présent sur CRITICAL/HIGH (forçable Pydantic)
    steps: list[str]
    helplines: list[Helpline]

class Finding(BaseModel):
    id: str                  # uuid stable par (kind, target)
    severity: Severity
    kind: FindingKind
    target_package: str
    target_label: str | None
    summary: str
    details: str             # markdown
    evidence: dict[str, Any] # data brute pour audit
    remediation: RemediationAdvice
    references: list[str]

class ScanReport(BaseModel):
    schema_version: Literal["1.0"]
    generated_at: datetime
    tool_version: str
    device: DeviceInfo
    signature_index: SignatureIndexMeta
    summary: dict[Severity, int]
    findings: list[Finding]
    safety_warning: str
```

## 5. Logique de détection

### 5.1 SignatureMatcher

Pour chaque app installée, on cherche un match sur trois axes :

| Axe | Source device | Source Echap | Sévérité |
|---|---|---|---|
| Nom de package exact | `pm list packages` | `samples[].apps[].id` | CRITICAL |
| Empreinte cert (SHA-256) | `dumpsys package` -> `signatures=` | `samples[].apps[].certificates[]` | CRITICAL |
| SHA-256 de l'APK | `adb pull base.apk` + sha256 local | `samples[].apps[].sha256` | CRITICAL |

Le hash APK n'est tenté que sur les apps **non-system** et **sideloadées**.
Si un match a déjà été trouvé sur package ou cert, on n'extrait pas l'APK
(performances). Le hash sert à attraper les stalkerware renommés.

Chaque match produit un `Finding(kind=SIGNATURE_HIT)` avec `evidence` =
`{matched_on, ioc_id, echap_yaml_path}`.

### 5.2 PermissionRiskScorer

Sur les apps **non-system**, calcul d'un score de profil de permissions pour
attraper les stalkerware qu'Echap ne connaît pas encore.

**Permissions sensibles (1 point chacune)** :

- `RECORD_AUDIO`
- `CAMERA` (background)
- `ACCESS_FINE_LOCATION` + `ACCESS_BACKGROUND_LOCATION`
- `READ_SMS` / `RECEIVE_SMS`
- `READ_CALL_LOG` / `READ_PHONE_STATE`
- `READ_CONTACTS`
- `READ_EXTERNAL_STORAGE` + `MANAGE_EXTERNAL_STORAGE`
- `PACKAGE_USAGE_STATS`
- `SYSTEM_ALERT_WINDOW`
- `BIND_ACCESSIBILITY_SERVICE` (via `enabled_accessibility_services`)
- `BIND_DEVICE_ADMIN` (via `dumpsys device_policy`)

**Facteurs aggravants (×2 sur le score)** :

- `installer_package` hors stores connus (sideloadée).
- App `hidden` (pas d'intent `LAUNCHER`).
- Label suspect (regex soft "System Service", "Device Health", "Sync", etc. —
  signal en `evidence`, pas bloquant seul).

**Seuils** :

- score ≥ 5 + accessibility OU device admin actif -> **HIGH**
- score ≥ 5 sans privilège système -> **MEDIUM**
- score ≥ 3 avec sideload -> **MEDIUM**
- sinon -> **LOW**

Chaque finding contient la liste des permissions matchées + le calcul du score
en `evidence`.

### 5.3 Side-channels

Findings indépendants à sévérité fixe :

- App non-system avec **device admin actif** -> `Finding(DEVICE_ADMIN, HIGH)`.
- App non-system avec **accessibility service actif** -> `Finding(ACCESSIBILITY_SVC, HIGH)`.
- App sideloadée non-system -> `Finding(SIDELOADED_APP, LOW)` (informatif).

Ces signaux nourrissent aussi le scoring du Permission Risk Scorer, mais ils
sortent en plus comme findings autonomes pour rester visibles si l'app n'a
aucune permission sensible (cas du stalkerware silencieux qui n'a que
device admin actif).

### 5.4 Gestion des faux positifs

- **Allowlist `signatures/legitimate_apps.yaml`** committée dans le repo, ~50
  apps légitimes (WhatsApp, Signal, Maps, antivirus connus). Une app allowlistée
  n'apparaît pas dans le rapport, sauf si elle match une signature Echap
  (qui prime).
- Apps **MDM d'entreprise** (Knox, Workspace ONE, Intune) -> catégorie
  `MDM_DETECTED` en `INFO`, avec mention "normal si téléphone pro".

## 6. CLI

```
stalkerware-detector scan [--serial SERIAL] [--output DIR]
                          [--format console,json,html]
                          [--with-apk-hash] [--no-network]
                          [--verbose] [--debug-trace FILE]
stalkerware-detector doctor          # vérifie adb, device, accès Echap
stalkerware-detector update-sigs     # force refresh repo Echap (ignore cache 24 h)
stalkerware-detector version
```

`--verbose` et `--debug-trace` sont globaux et acceptés par toutes les
sous-commandes.

**Défauts** :

- Si un seul device connecté, on le prend ; sinon prompt ou erreur si stdin
  non-tty.
- Sorties dans `./reports/scan-YYYYMMDD-HHMMSS.{json,html}` + console.
- APK hashing **désactivé par défaut** (peut éveiller l'attention sur le
  téléphone via notification ADB) ; activable via `--with-apk-hash`.
- `--no-network` : utilise le cache Echap existant, échoue si pas de cache.

**Codes retour** :

| Code | Signification |
|---|---|
| 0 | Aucun finding |
| 1 | Findings LOW / MEDIUM uniquement |
| 2 | Au moins un finding HIGH |
| 3 | Au moins un finding CRITICAL |
| 10 | adb absent du PATH |
| 11 | Aucun device connecté |
| 12 | Device `unauthorized` |
| 13 | Device `offline` |
| 14 | Plusieurs devices, pas de `--serial`, stdin non-tty |
| 20 | Réseau KO et pas de cache Echap |
| 21 | Cache Echap corrompu et impossible à re-fetch |

## 7. Gestion d'erreurs

| Erreur | Détection | Comportement |
|---|---|---|
| `adb` absent | `shutil.which("adb")` | Message FR + lien platform-tools, exit 10 |
| `adb` ancien | parse `adb version` | Warning, continue |
| Device unauthorized | parsing `adb devices` | Message + retry après ENTER |
| Device offline | parsing `adb devices` | Message "rebrancher le câble" |
| Réseau KO Echap | exception requests/git | Si cache présent -> warn + continue ; sinon exit 20 |
| Cache YAML corrompu | YAML parse error | Suppression cache + re-fetch, sinon exit 21 |
| `dumpsys X` échoue sur 1 package | parsing stderr | Logue warning, finding INFO `collect_partial`, continue |
| Permission refusée sur pull APK | adb stderr | Skip, note `apk_hash_skipped` dans evidence |
| `adb pull` timeout (> 30 s par APK) | subprocess timeout | Skip cet APK, continue |
| Analyzer crash | try/except global par analyzer | Logue stacktrace + Finding(INFO, `analyzer_error`), les autres tournent |

**Logging** :

- INFO par défaut (rich console).
- `--verbose` : DEBUG, dump commandes ADB (stdout/stderr tronqués à 500 chars).
- `--debug-trace FILE` : tout dans un fichier log pour support.

## 8. Sécurité & éthique

1. **Aucune télémétrie sortante.** Le scanner ne contacte que (a) le repo Echap
   public, (b) `adb` local. Documenté README et rapport.
2. **Pas de pull de données utilisateur.** On extrait uniquement `base.apk`
   (binaire de l'app) pour hashing, jamais `/data/data/<pkg>/`. Audit du code
   par grep `pull` doit le confirmer.
3. **Rapport HTML sans JavaScript externe.** Tout est inline (CSS + images
   base64). Un rapport ne doit jamais "appeler maison" quand la victime
   l'ouvre.
4. **Bannière safety-first non-escamotable** en tête de tout rapport contenant
   ≥ 1 finding CRITICAL ou HIGH :

   > ⚠ **Avant de désinstaller quoi que ce soit** : si vous suspectez un
   > harcèlement, la disparition du stalkerware peut alerter la personne qui
   > l'a installé et déclencher une réaction dangereuse. Contactez d'abord
   > le **3919** (violences faites aux femmes, gratuit, anonyme) ou la
   > **police (17)** si vous êtes en danger immédiat. Conservez ce rapport
   > comme preuve avant toute action.

5. **APK hashing désactivé par défaut sur Android ≥ 11** — le `pull` peut
   afficher une notification ADB persistante sur le téléphone, ce qui peut
   être visible par l'agresseur. Trade-off documenté.
6. **Allowlist publique et auditable** : `legitimate_apps.yaml` committé dans
   le repo, pas chargé dynamiquement. Personne ne peut allowlister un
   stalkerware via MITM.
7. **Pas de stockage de PII.** Le rapport contient : modèle, version Android,
   noms de packages, permissions. Pas d'IMEI, pas de numéro de tél, pas de
   compte Google. Le serial ADB est tronqué (4 derniers chars).

## 9. Tests

- **Unit tests collectors** avec fixtures dumps réels capturés une fois
  (`tests/fixtures/dumpsys_package_legit.txt`, etc.).
- **Unit tests signature_match** avec mini-repo Echap fixture (3-4 YAML).
- **Unit tests permission_risk** avec inputs synthétiques validant chaque seuil.
- **Tests reporters** : snapshot tests sur HTML / JSON (golden files).
- **Test d'intégration end-to-end** : `@pytest.mark.requires_device`,
  skip par défaut en CI, doc dans le README pour le lancer manuellement.
- **Pas de mock subprocess.** On mock `device.adb.run_shell()` qui renvoie du
  texte.

**Couverture cible** : ≥ 80 % sur `analyzers/` et `signatures/`.

## 10. Phasage

| Phase | Livrable | Durée | Critère d'acceptation |
|---|---|---|---|
| 1 | Skeleton bootable : pyproject, CI, `cli doctor`, `update-sigs`, `device/`, README minimal | ~½ j | `doctor` connecté affiche model + Android version + path cache |
| 2 | Détection signatures seule (package + cert, pas APK hash), collector packages, console reporter basique | ~1 j | Téléphone sain = 0 finding CRITICAL ; app de test sideloadée au nom Echap = finding CRITICAL |
| 3 | Collectors permissions/device_admin/accessibility, PermissionRiskScorer, side-channels, allowlist | ~1 j | Téléphone sain = 0 finding HIGH/CRITICAL ; app de test très permissive = HIGH |
| 4 | ScanReport complet, advisor, JSON/HTML reporters, snapshot tests, APK hashing optionnel via `--with-apk-hash` (désactivé par défaut) | ~1 j | Scan = 3 sorties cohérentes, HTML lisible, safety-first visible sur HIGH+ |

## 11. Critères de succès v1

1. Scan complet d'un Android ≥ 9 en < 3 minutes sans APK hashing.
2. 0 finding CRITICAL/HIGH sur 3 téléphones sains de référence.
3. Détection effective sur 5 stalkerware Echap installés en sideload pour
   test.
4. Rapport HTML lisible par une personne non-technique (test sur 1-2
   personnes hors tech).
5. Couverture tests ≥ 80 % sur `analyzers/` + `signatures/`.
6. CI verte sur Linux, Windows et macOS.

## 12. Livrable final

- Repo public `github.com/mathieumuzelet-hue/stalkerware-detector`, GPL-3.0.
- README : présentation, install, usage, FAQ éthique, limites, liens d'aide.
- Releases tagées avec wheel publiée (au moins GitHub Releases ; PyPI v1.1).
- Démo : asciinema d'un scan complet.

## 13. Références

- Coalition Against Stalkerware : <https://stopstalkerware.org/>
- Echap (FR, asso) : <https://echap.eu.org/>
- Repo signatures Echap : <https://github.com/AssoEchap/stalkerware-indicators>
- MVT (Amnesty) : <https://github.com/mvt-project/mvt>
- TinyCheck (Kaspersky) : <https://github.com/KasperskyLab/TinyCheck>
- 3919 (violences faites aux femmes, FR) : <https://www.solidaritefemmes.org/>
- Centre Hubertine Auclert : <https://www.centre-hubertine-auclert.fr/>
