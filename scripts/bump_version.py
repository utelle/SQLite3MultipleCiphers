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


def update_config(config: dict, project_v: str) -> dict:

    config["version"] = project_v

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
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: update_config.py <project_version>"
        )

    project_version = validate_sqlite3mc_version(sys.argv[1])

    config = load_config(CONFIG_FILE)

    new_config = update_config(
        json.loads(json.dumps(config)),  # shallow safe copy
        project_version
    )

    # Diff output (CI / PR-friendly)
    print_diff(config, new_config)

    # Write
    write_config_atomic(CONFIG_FILE, new_config)

    print("\nUpdated config:")
    print(f"  SQLite3MC version : {project_version}")


if __name__ == "__main__":
    main()
