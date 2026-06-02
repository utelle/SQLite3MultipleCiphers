import json
import sys
import re
from pathlib import Path

CONFIG_FILE = Path("config.json")

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(\.\d+)?$")
ANDROID_CHECKIN_RE = re.compile(r"^[0-9a-fA-F]{10}$")


# ----------------------------
# Validation
# ----------------------------

def validate_sqlite3mc_version(v: str) -> str:
    if not VERSION_RE.fullmatch(v):
        raise ValueError(f"Invalid version format: {v}. Expected x.y.z or x.y.z.w")

    parts = v.split(".")
    if len(parts) < 3:
        raise ValueError("Version must have at least 3 components")

    return v


def validate_sqlite_version(v: str) -> str:
    if not VERSION_RE.fullmatch(v):
        raise ValueError(f"Invalid version format: {v}. Expected x.y.z or x.y.z.w")

    parts = v.split(".")
    if len(parts) < 3:
        raise ValueError("Version must have at least 3 components")

    major = int(parts[0])
    if major != 3:
        raise ValueError(f"Unsupported SQLite major version: {major} (must be 3)")

    return v


def validate_android_checkin(v: str) -> str:
    if not isinstance(v, str):
        raise ValueError("Android check-in must be a string")

    v = v.strip().lower()

    if not ANDROID_CHECKIN_RE.fullmatch(v):
        raise ValueError(
            f"Invalid Android check-in: {v}. Expected exactly 10 hexadecimal characters"
        )

    return v


# ----------------------------
# Config handling
# ----------------------------

def load_config(path: Path) -> dict:
    if not path.exists():
        raise RuntimeError(
            f"Missing config file: {path}. "
            "A valid base configuration is required to perform updates."
        )

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in {path}: {e}") from e


def update_config(config: dict, project_v: str, sqlite_v: str, android_v: str) -> dict:
    config.setdefault("sqlite", {})
    config.setdefault("sqlite", {}).setdefault("android", {})

    config["version"] = project_v
    config["sqlite"]["version"] = sqlite_v
    config["sqlite"]["android"]["check-in"] = android_v

    return config


def write_config_atomic(path: Path, config: dict):
    tmp = path.with_suffix(".tmp")

    tmp.write_text(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8"
    )

    tmp.replace(path)


# ----------------------------
# Diff helper
# ----------------------------

def print_diff(old: dict, new: dict):
    def get(d, path):
        for p in path:
            d = d.get(p, {})
        return d if isinstance(d, str) else str(d)

    changes = []

    def compare(path, label):
        old_v = get(old, path)
        new_v = get(new, path)
        if old_v != new_v:
            changes.append((label, old_v, new_v))

    compare(["version"], "project.version")
    compare(["sqlite", "version"], "sqlite.version")
    compare(["sqlite", "android", "check-in"], "sqlite.android.check-in")

    if not changes:
        print("No changes detected.")
        return

    print("\nProposed changes:")
    for label, old_v, new_v in changes:
        print(f"  {label}: {old_v} → {new_v}")


# ----------------------------
# Main
# ----------------------------

def main():
    if len(sys.argv) != 4:
        raise SystemExit(
            "Usage: update_config.py <project_version> <sqlite_version> <android_check_in>"
        )

    project_version = validate_sqlite3mc_version(sys.argv[1])
    sqlite_version = validate_sqlite_version(sys.argv[2])
    android_checkin = validate_android_checkin(sys.argv[3])

    config = load_config(CONFIG_FILE)

    new_config = update_config(
        json.loads(json.dumps(config)),  # shallow safe copy
        project_version,
        sqlite_version,
        android_checkin
    )

    # Diff output (CI / PR-friendly)
    print_diff(config, new_config)

    # Write
    write_config_atomic(CONFIG_FILE, new_config)

    print("\nUpdated config:")
    print(f"  SQLite3MC version : {project_version}")
    print(f"  SQLite version    : {sqlite_version}")
    print(f"  Android Check-In  : {android_checkin}")


if __name__ == "__main__":
    main()
