"""Pick the right device, capture its OS metadata, expose a DeviceSession."""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import adb


class DeviceSelectionError(RuntimeError):
    """Base class for device selection failures."""


class NoDeviceError(DeviceSelectionError):
    pass


class AmbiguousDeviceError(DeviceSelectionError):
    pass


class DeviceUnauthorizedError(DeviceSelectionError):
    pass


@dataclass(frozen=True)
class DeviceInfo:
    manufacturer: str | None
    model: str | None
    android_release: str | None
    sdk_int: int | None
    build_id: str | None
    security_patch: str | None


@dataclass(frozen=True)
class DeviceSession:
    serial: str
    info: DeviceInfo


_GETPROP_LINE = re.compile(r"^\[(?P<key>[^\]]+)\]:\s*\[(?P<val>[^\]]*)\]\s*$")


def parse_getprop(output: str) -> DeviceInfo:
    props: dict[str, str] = {}
    for line in output.splitlines():
        m = _GETPROP_LINE.match(line)
        if m:
            props[m.group("key")] = m.group("val")
    sdk_raw = props.get("ro.build.version.sdk")
    return DeviceInfo(
        manufacturer=props.get("ro.product.manufacturer"),
        model=props.get("ro.product.model"),
        android_release=props.get("ro.build.version.release"),
        sdk_int=int(sdk_raw) if sdk_raw and sdk_raw.isdigit() else None,
        build_id=props.get("ro.build.id"),
        security_patch=props.get("ro.build.version.security_patch"),
    )


def redact_serial(serial: str) -> str:
    if len(serial) <= 4:
        return serial
    return ("*" * (len(serial) - 4)) + serial[-4:]


def select_device(
    devices: list[adb.DeviceEntry],
    *,
    requested: str | None,
    interactive: bool,
) -> str:
    if not devices:
        raise NoDeviceError(
            "No device connected. Plug your phone via USB and enable USB debugging."
        )

    if requested is not None:
        for d in devices:
            if d.serial == requested:
                if d.state == "device":
                    return d.serial
                raise _raise_for_state(d)
        raise DeviceSelectionError(
            f"Requested serial {requested!r} not connected. Seen: "
            f"{[d.serial for d in devices]}"
        )

    if len(devices) == 1:
        d = devices[0]
        if d.state == "device":
            return d.serial
        raise _raise_for_state(d)

    if not interactive:
        raise AmbiguousDeviceError(
            f"{len(devices)} devices connected, use --serial to choose one of "
            f"{[d.serial for d in devices]}"
        )

    raise AmbiguousDeviceError("Interactive selection not implemented in v0.1; pass --serial")


def _raise_for_state(d: adb.DeviceEntry) -> DeviceSelectionError:
    if d.state == "unauthorized":
        return DeviceUnauthorizedError(
            f"Device {d.serial} is unauthorized. Confirm the RSA fingerprint prompt on your phone."
        )
    return DeviceSelectionError(f"Device {d.serial} is in state {d.state!r}.")


def connect(*, requested_serial: str | None, interactive: bool) -> DeviceSession:
    devices = adb.list_devices()
    serial = select_device(devices, requested=requested_serial, interactive=interactive)
    info = parse_getprop(adb.run_shell(serial, "getprop"))
    return DeviceSession(serial=serial, info=info)
