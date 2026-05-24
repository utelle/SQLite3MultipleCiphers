import json
import os
from pathlib import Path

CONFIG_FILE = Path("config.json")


def sqlite_raw(v: str) -> str:
    parts = v.split(".")
    major = int(parts[0])
    minor = int(parts[1])
    patch = int(parts[2])
    build = int(parts[3]) if len(parts) > 3 else 0

    return f"{major:03}{minor:02}{patch:02}{build:02}00"


def main():
    config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))

    sqlite_version = config["sqlite"]["version"]

    # URLs aus config (kein Hardcoding!)
    official = config["sqlite"]["sources"]["official"]["url"]
    github = config["sqlite"]["sources"]["github"]["url"]

    ctx = {
        "SQLITE_VERSION": sqlite_version,
        "SQLITE_VERSION_RAW": sqlite_raw(sqlite_version),
        "SQLITE_URL_OFFICIAL": official,
        "SQLITE_URL_GITHUB": github,
    }

    with open(os.environ["GITHUB_ENV"], "a") as f:
        for k, v in ctx.items():
            f.write(f"{k}={v}\n")

    print("Build context exported")


if __name__ == "__main__":
    main()