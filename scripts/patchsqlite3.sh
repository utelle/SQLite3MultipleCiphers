#!/bin/sh
# Generate patched sqlite3.c from SQLite3 amalgamation and write it to stdout.
# Usage: ./script/patchsqlite3.sh sqlite3.c >sqlite3patched.c

INPUT="$([ "$#" -eq 1 ] && echo "$1" || echo "sqlite3.c")"
if ! [ -f "$INPUT" ]; then
  echo "Usage: $0 <SQLITE3_AMALGAMATION>" >&2
  echo " e.g.: $0 sqlite3.c" >&2
  exit 1
fi

die() {
    echo "[-]" "$@" >&2
    exit 2
}

# 1) Intercept VFS pragma handling
# 2) Add handling of KEY parameter in ATTACH statements
sed 's/sqlite3_file_control\(.*SQLITE_FCNTL_PRAGMA\)/sqlite3mcFileControlPragma\1/' "$INPUT" \
    | sed '/sqlite3mcFileControlPragma/i \  extern int sqlite3mcFileControlPragma(sqlite3*, const char*, int, void*);' \
    | sed '/sqlite3_free_filename( zPath );/i \\n  \/\* Handle KEY parameter. \*\/\n  if( rc==SQLITE_OK ){\n    extern int sqlite3mcHandleAttachKey(sqlite3*, const char*, const char*, sqlite3_value*, char**);\n    rc = sqlite3mcHandleAttachKey(db, zName, zPath, argv[2], &zErrDyn);\n  }'
