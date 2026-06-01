import json
import sys
import re
from pathlib import Path

CONFIG_FILE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("config.json")

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(\.\d+)?$")
ANDROID_CHECKIN_RE = re.compile(r"^[0-9a-fA-F]{10}$")


# ----------------------------
# error handling
# ----------------------------

def error(msg: str):
    raise SystemExit(f"[CONFIG VALIDATION ERROR] {msg}")


# ----------------------------
# schema validation (structure)
# ----------------------------

REQUIRED_SCHEMA = {
    "version": str,
    "sqlite": {
        "version": str,
        "android": {
            "check-in": str
        },
        "sources": {
            "official": {"url": str},
            "github": {"url": str},
            "android": {"url": str}
        }
    },
    "icu": {
        "version": str,
        "sources": {
            "official": {"url": str}
        }
    }
}


def validate_structure(obj, schema, path="root"):
    if isinstance(schema, dict):
        if not isinstance(obj, dict):
            error(f"{path} must be an object")

        for key, sub_schema in schema.items():
            if key not in obj:
                error(f"Missing key '{key}' at {path}")

            validate_structure(obj[key], sub_schema, f"{path}.{key}")

    else:
        # leaf type check
        if schema == str and not isinstance(obj, str):
            error(f"{path} must be string")


# ----------------------------
# value validation
# ----------------------------

def validate_version(v: str, name: str):
    if not VERSION_RE.fullmatch(v):
        error(f"{name}: invalid version '{v}' (expected x.y.z or x.y.z.w)")


def validate_android(v: str):
    if not ANDROID_CHECKIN_RE.fullmatch(v):
        error(f"Android Check-In invalid: '{v}' (expected 10 hex chars)")


# ----------------------------
# main
# ----------------------------

def main():
    if not CONFIG_FILE.exists():
        error(f"Config file not found: {CONFIG_FILE}")

    try:
        config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        error(f"Invalid JSON: {e}")

    # ----------------------------
    # 1. STRUCTURE CHECK (CRITICAL)
    # ----------------------------
    validate_structure(config, REQUIRED_SCHEMA)

    # ----------------------------
    # 2. VALUE CHECKS
    # ----------------------------

    validate_version(config["version"], "SQLite3MC version")

    validate_version(config["sqlite"]["version"], "SQLite version")

    validate_android(config["sqlite"]["android"]["check-in"])

    # ----------------------------
    # optional rule checks
    # ----------------------------
    if not config["sqlite"]["version"].startswith("3."):
        error(f"SQLite version must start with 3.x: {config['sqlite']['version']}")

    print("Config validation OK")


if __name__ == "__main__":
    main()
