import os
import re
from pathlib import Path

VERSION = os.environ.get("SQLITE3MC_VERSION")
if not VERSION:
    raise RuntimeError("SQLITE3MC_VERSION is not set")


def update_file(path: Path, pattern: str, replacement_fn, description: str):
    content = path.read_text(encoding="utf-8")

    new_content, count = re.subn(pattern, replacement_fn, content)

    if count == 0:
        raise RuntimeError(f"No match found in {path} for {description}")

    path.write_text(new_content, encoding="utf-8")
    print(f"[OK] Updated {description} in {path}")


# ---------------------------
# 1. CMakeLists.txt
# ---------------------------
cmake_file = Path("CMakeLists.txt")

cmake_pattern = r'(set\s*\(\s*SQLITE3MC_VERSION\s*")[0-9]+\.[0-9]+\.[0-9]+("\s*\))'

cmake_replacement = rf'\g<1>{VERSION}\2'

update_file(
    cmake_file,
    cmake_pattern,
    cmake_replacement,
    "CMake SQLITE3MC_VERSION"
)


# ---------------------------
# 2. configure.ac
# ---------------------------
configure_file = Path("configure.ac")

# AC_INIT([sqlite3mc], [2.3.5], [...])
ac_pattern = r'(AC_INIT\(\[sqlite3mc\],\s*\[)[0-9]+\.[0-9]+\.[0-9]+(\],)'

ac_replacement = rf'\g<1>{VERSION}\2'

update_file(
    configure_file,
    ac_pattern,
    ac_replacement,
    "Autotools AC_INIT version"
)