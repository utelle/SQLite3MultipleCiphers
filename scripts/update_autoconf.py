#!/usr/bin/env python3

import os
import re
from pathlib import Path

sqlite3mc_version = os.environ["SQLITE3MC_VERSION"]
sqlite_version = os.environ["SQLITE_VERSION"]

#
# File: VERSION
# contains exactly one line with the version numbe
#
Path("autoconf/VERSION").write_text(sqlite3mc_version + "\n")

#
# File: sqlite3rc.h
# contains 3 lines, the version number on the second line
#
rc_header_file = Path("autoconf/sqlite3rc.h")

resource_version = sqlite_version.replace(".", ",")

rc_header_file.write_text("#ifndef SQLITE_RESOURCE_VERSION\n")
rc_header_file.write_text("#define SQLITE_RESOURCE_VERSION {resource_version}\n")
rc_header_file.write_text("#endif\n")
