"""Keep Minecraft's multiplayer advisory disabled in the distributed defaults."""

import hashlib
import json
import re
import zipfile


PROFILE = "config/defaultsettings.json"
OPTION = b"skipMultiplayerWarning:"
RECORD = re.compile(rb"(?m)^skipMultiplayerWarning:([^\r\n]*)")


def setting_path(descriptor, metadata):
    if (descriptor.get("minecraftVersion"), descriptor.get("loader", {}).get("type")) != ("1.20.1", "forge"):
        raise ValueError("Review the multiplayer advisory policy for the new Minecraft platform")
    profile = json.loads(metadata)["mainProfile"]
    if not isinstance(profile, str) or not re.fullmatch(r"[A-Za-z0-9 _-]+", profile):
        raise ValueError("Invalid DefaultSettings profile name")
    return f"config/defaultsettings/{profile}/options.txt"


def apply(raw):
    matches = list(RECORD.finditer(raw))
    if len(matches) > 1:
        raise ValueError("Duplicate skipMultiplayerWarning in DefaultSettings")
    if matches:
        start, end = matches[0].span(1)
        return raw[:start] + b"true" + raw[end:]
    newline = b"\r\n" if b"\r\n" in raw else b"\n"
    separator = newline if raw and not raw.endswith(b"\n") else b""
    return raw + separator + OPTION + b"true" + newline


def verify(out, manifest):
    assets = [item for item in manifest["assets"] if PROFILE in item["covers"]]
    if len(assets) != 1 or assets[0]["kind"] != "zipRoot":
        raise ValueError("DefaultSettings config archive is missing or ambiguous")
    with zipfile.ZipFile(out / "assets" / assets[0]["name"]) as archive:
        def read(relative):
            rows = [row for row in manifest["files"] if row["path"] == relative]
            if (archive.namelist().count(relative) != 1 or len(rows) != 1
                    or assets[0]["covers"].count(relative) != 1):
                raise ValueError("DefaultSettings entry must be shipped once: " + relative)
            raw = archive.read(relative)
            if len(raw) != rows[0]["sizeBytes"] or hashlib.sha256(raw).hexdigest() != rows[0]["sha256"]:
                raise ValueError("Staged DefaultSettings entry differs from the manifest: " + relative)
            return raw

        raw = read(setting_path(manifest, read(PROFILE)))
    if [m[1] for m in RECORD.finditer(raw)] != [b"true"]:
        raise ValueError("The staged DefaultSettings options must set skipMultiplayerWarning:true")
