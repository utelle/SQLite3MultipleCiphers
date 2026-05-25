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

    return f"{major}{minor:02}{patch:02}{build:02}"


def main():
    config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))

    sqlite_version = config["sqlite"]["version"]

    # URLs aus config (kein Hardcoding!)
    sqlite_official = config["sqlite"]["sources"]["official"]["url"]
    sqlite_github = config["sqlite"]["sources"]["github"]["url"]

    icu_version = config["icu"]["version"]
    icu_official = config["icu"]["sources"]["official"]["url"]

    ctx = {
        "SQLITE_VERSION": sqlite_version,
        "SQLITE_VERSION_RAW": sqlite_raw(sqlite_version),
        "SQLITE_URL_OFFICIAL": sqlite_official,
        "SQLITE_URL_GITHUB": sqlite_github,
        "ICU_VERSION": icu_version,
        "ICU_TEMPLATE": icu_official,
        "ICU_URL_WIN32": icu_url_template.format(
            ICU_VERSION=icu_version,
            PLATFORM="win32"
        ),
        "ICU_URL_WIN64": icu_url_template.format(
            ICU_VERSION=icu_version,
            PLATFORM="win64"
        ),
    }

    with open(os.environ["GITHUB_ENV"], "a") as f:
        for k, v in ctx.items():
            f.write(f"{k}={v}\n")

    print("Build context exported")


if __name__ == "__main__":
    main()