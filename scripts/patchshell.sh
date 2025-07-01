#!/bin/sh
# Generate patched shell.c from SQLite3 amalgamation distribution and write it to stdout.
# Usage: ./script/patchshell.sh shell.c >shellpatched.c

INPUT="$([ "$#" -eq 1 ] && echo "$1" || echo "shell.c")"
if ! [ -f "$INPUT" ]; then
  echo "Usage: $0 <SQLITE3_SHELL_AMALGAMATION>" >&2
  echo " e.g.: $0 shell.c" >&2
  exit 1
fi

die() {
    echo "[-]" "$@" >&2
    exit 2
}

sed -e '/^      sputf(stdout, "SQLite version/{n;N;d}' "$INPUT" \
  | sed '/#ifdef SQLITE_CUSTOM_INCLUDE/!{p;d;};n;n;n;a #if SQLITE3MC_USE_MINIZ != 0 && !defined(SQLITE_ENABLE_COMPRESS)\n#include "miniz.c"\n#ifdef SQLITE_HAVE_ZLIB\n#undef SQLITE_HAVE_ZLIB\n#endif\n#define SQLITE_HAVE_ZLIB 1\n#endif\n' \
  | sed '/#include <zlib.h>/c #include "zlibwrap.h"' \
  | sed '/^      sqlite3_fprintf(stdout,$/c \      extern const char* sqlite3mc_version();\n      sqlite3_fprintf(stdout,' \
  | sed '/^            "SQLite version/c \            "SQLite version \%s \%.19s" \/\*extra-version-info\*\/\n            " (\%s)\\n" \/\*SQLite3-Multiple-Ciphers-version-info\*\/' \
  | sed '/^            sqlite3_libversion(), sqlite3_sourceid());/c \            sqlite3_libversion(), sqlite3_sourceid(), sqlite3mc_version());' \
  | sed '/^          sqlite3_libversion(), sqlite3_sourceid());/a \    extern const char* sqlite3mc_version();\n    sqlite3_fprintf(p->out, "\%s\\n", sqlite3mc_version());' \
  | sed '/Begin ..\/ext\/misc\/shathree.c/i #ifndef SQLITE_OMIT_SHELL_SHATHREE' \
  | sed '/End ..\/ext\/misc\/shathree.c/a #endif' \
  | sed '/Begin ..\/ext\/misc\/series.c/i #ifndef SQLITE_OMIT_SHELL_SERIES' \
  | sed '/End ..\/ext\/misc\/series.c/a #endif' \
  | sed '/Begin ..\/ext\/misc\/regexp.c/i #ifndef SQLITE_OMIT_SHELL_REGEXP' \
  | sed '/End ..\/ext\/misc\/regexp.c/a #endif' \
  | sed '/sqlite3_shathree_init(p->db, 0, 0);/i #ifndef SQLITE_OMIT_SHELL_SHATHREE' \
  | sed '/sqlite3_shathree_init(p->db, 0, 0);/a #endif' \
  | sed '/sqlite3_series_init(p->db, 0, 0);/i #ifndef SQLITE_OMIT_SHELL_SERIES' \
  | sed '/sqlite3_series_init(p->db, 0, 0);/a #endif' \
  | sed '/sqlite3_regexp_init(p->db, 0, 0);/i #ifndef SQLITE_OMIT_SHELL_REGEXP' \
  | sed '/sqlite3_regexp_init(p->db, 0, 0);/a #endif'
