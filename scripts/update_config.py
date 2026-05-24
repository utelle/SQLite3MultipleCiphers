import json
import sys
import re
from pathlib import Path

CONFIG_FILE = Path("config.json")

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(\.\d+)?$")

def validate_version(v: str):
    if not VERSION_RE.match(v):
        raise ValueError(
            f"Invalid version format: {v}. Expected x.y.z or x.y.z.w"
        )

    parts = v.split(".")

    if len(parts) < 3:
        raise ValueError("Version must have at least 3 components")

    major = int(parts[0])

    if major != 3:
        raise ValueError(f"Unsupported major version: {major} (must be 3)")

    return parts


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: update_config.py <sqlite_version>")

    version = sys.argv[1]
    validate_version(version)

    if CONFIG_FILE.exists():
        config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    else:
        config = {}

    config.setdefault("sqlite", {})
    config["sqlite"]["version"] = version

    CONFIG_FILE.write_text(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8"
    )

    print(f"Updated SQLite version to {version}")


if __name__ == "__main__":
    main()
