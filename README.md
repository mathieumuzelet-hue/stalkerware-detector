# stalkerware-detector

Scan an Android phone connected via USB to detect installed stalkerware. Uses the
Coalition Against Stalkerware (Echap) signature database, plus a permission
heuristic to flag suspect apps the signature DB doesn't know yet.

**Status:** v0.1 — French CLI/HTML output. Detection logic is signature + permission
profile only (no network capture, no iOS, no full forensic).

## Who this is for

Journalists, security responders, IT-savvy folks helping a friend or relative.
The HTML report is written so it can be shared with a victim who is not technical.

## Prerequisites

- Python 3.11+
- [Android SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools)
  (provides `adb`) — must be on your PATH
- The phone must have **USB debugging enabled** (Settings > About > tap "Build
  number" 7 times to unlock Developer options, then Developer options > USB debugging)
- The user must accept the RSA fingerprint prompt on the phone

## Install

```bash
poetry install
poetry run stalkerware-detector doctor
```

`doctor` verifies your setup: that `adb` is on PATH, that a device is connected
and authorized, and that the OS metadata can be read.

## Usage

```bash
# Run a full scan with default options
poetry run stalkerware-detector scan

# Specify a target device when several are connected
poetry run stalkerware-detector scan --serial ABCD1234EFGH

# Pull and hash every non-store APK (slower, may trigger ADB notification on phone)
poetry run stalkerware-detector scan --with-apk-hash

# Refresh the Echap signature database now (otherwise refreshed every 24h)
poetry run stalkerware-detector update-sigs
```

Reports land in `./reports/scan-<timestamp>.{json,html}` and are also printed to
the terminal.

## Exit codes

| Code | Meaning |
|---|---|
| 0  | No finding |
| 1  | LOW/MEDIUM findings only |
| 2  | At least one HIGH finding |
| 3  | At least one CRITICAL finding |
| 10 | `adb` missing |
| 11 | No device connected |
| 12 | Device unauthorized |
| 13 | Device offline |
| 14 | Multiple devices, no `--serial` provided |
| 20 | Network unreachable and no signature cache |
| 21 | Signature cache corrupted |
| 22 | Signature index empty (run `update-sigs`) |

## Safety

- The tool emits no telemetry. It contacts only (a) the public Echap GitHub repo
  for signature updates and (b) your local `adb`. Inspect the source to verify.
- HTML reports contain zero external resources (no script, no remote CSS/images).
- We never pull user data from `/data/data/<pkg>/`; only `base.apk` files when
  `--with-apk-hash` is set.
- Device serials are redacted to the last 4 characters in reports.

## FAQ

**Why not just use MVT?**
MVT (Amnesty's Mobile Verification Toolkit) is a full forensic suite. We focus
narrowly on stalkerware detection with a victim-friendly HTML output.

**Why not TinyCheck?**
TinyCheck analyses network traffic via Wi-Fi. We complement it with a device-side
scan over USB.

**What if I'm in danger right now?**
Stop, do not uninstall anything visible to the suspected installer. Call:
- France — **3919** (free, anonymous, violence against women hotline)
- France — **17** (police, in immediate danger)

## License

GPL-3.0-or-later. See LICENSE.
