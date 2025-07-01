# Configuration for SQLite3 Multiple Ciphers (sqlite3mc)

proc sqlite3mc-handle-default-cipher {} {
  if {[proj-opt-was-provided default-cipher]} {
    set dc [opt-val default-cipher chacha20]
    set dcv CHACHA20
    msg-checking "    Default cipher: "
    switch -exact -- $dc {
      aes128cbc { set dcv AES128    }
      aes256cbc { set dcv AES256    }
      chacha20  { set dcv CHACHA20  }
      sqlcipher { set dcv SQLCIPHER }
      rc4       { set dcv RC4       }
      ascon128  { set dcv ASCON128  }
      aegis     { set dcv AEGIS     }
      default {
        user-error "Invalid --default-cipher value '$dc'. Use one of: aes128cbc, aes256cbc, chacha20, sqlcipher, rc4, ascon128, aegis"
      }
    }
    msg-result $dc
    sqlite-add-feature-flag -DCODEC_TYPE=CODEC_TYPE_$dcv
  } {
    msg-result "    Default cipher: chacha20"
    sqlite-add-feature-flag -DCODEC_TYPE=CODEC_TYPE_CHACHA20
  }
}

proc sqlite-custom-flags {} {
  # If any existing --flags require different default values
  # then call:
  options-defaults {
    with-tempstore yes
  }
  # ^^^ That will replace the default value but will not update
  # the --help text, which may lead to some confusion:
  # https://github.com/msteveb/autosetup/issues/77

  return {
   {*} {
     column-metadata=1  => {Disable column meta data}
     secure-delete=1    => {Disable secure delete}
     use-uri=1          => {Disable URI filenames}
     aes-hw-support=1   => {Disable AES hardware support}
     builtin-ciphers=1  => {Disable all builtin ciphers}
     dynamic-ciphers    => {Enable dynamic ciphers}
     default-cipher:=chacha20 => {Default cipher (aes128cbc, aes256cbc, chacha20, sqlcipher, rc4, ascon128, aegis)}

     cipher-aes128cbc=1 => {Disable cipher AES128CBC}
     cipher-aes256cbc=1 => {Disable cipher AES256CBC}
     cipher-chacha20=1  => {Disable cipher ChaCha20}
     cipher-sqlcipher=1 => {Disable cipher SQLCipher}
     cipher-rc4=1       => {Disable cipher RC4}
     cipher-ascon128=1  => {Disable cipher ASCON128}
     cipher-aegis=1     => {Disable cipher AEGIS}

     carray             => {Enable the CARRAY extension}
     extfunc            => {Enable the EXTFUNC extension}
     regexp             => {Enable the REGEXP extension}
     series             => {Enable the SERIES extension}
     sha3               => {Enable the SHA3 extension}
     uuid               => {Enable the UUID extension}
   }
  }; #see below
}

proc sqlite-custom-handle-flags {} {
  # Select memory for temporary tables, unless that option was explicitly set
  if {[proj-opt-was-provided with-tempstore]} {
  } {
    sqlite-add-feature-flag -DSQLITE_TEMP_STORE=2
    msg-result "Use an in-RAM database for temporary tables? yes"
  }

  # Check and show the options for SQLite3MC
  msg-result "Options for SQLite3 Multiple Ciphers..."

  # Enable all extensions, if option ALL was given
  proj-if-opt-truthy all {
    foreach boolFlag { carray extfunc regexp series sha3 uuid } {
      if {![proj-opt-was-provided $boolFlag]} {
        proj-opt-set $boolFlag 1
      }
    }
  }

  msg-result "  Extensions..."
  foreach {boolFlag featureFlag shellFeatureFlag ifSetEvalThis} [proj-strip-hash-comments {
    carray  -DSQLITE_ENABLE_CARRAY  "" {}
    extfunc -DSQLITE_ENABLE_EXTFUNC "" {}
    uuid    -DSQLITE_ENABLE_UUID    "" {}
    # The following 3 extensions are unconditionally enabled in the SQLite shell
    # If enabled here they'd cause duplicate symbols in library and shell
    # Therefore exclude them from the shell source if necessary
    regexp  -DSQLITE_ENABLE_REGEXP  -DSQLITE_OMIT_SHELL_REGEXP {}
    series  -DSQLITE_ENABLE_SERIES  -DSQLITE_OMIT_SHELL_SERIES {}
    sha3    -DSQLITE_ENABLE_SHA3    -DSQLITE_OMIT_SHELL_SHATHREE {}
  }] {
    proj-if-opt-truthy $boolFlag {
      if {0 != [eval $ifSetEvalThis]} {
        sqlite-add-feature-flag $featureFlag
        if {$shellFeatureFlag ne ""} {
          sqlite-add-feature-flag -shell $shellFeatureFlag
        }
        msg-result "    + $boolFlag"
      }
    } {
      msg-result "    - $boolFlag"
    }
  }

  # Check whether the all builtin ciphers are disabled
  msg-result "  Cipher configuration..."
  proj-if-opt-truthy builtin-ciphers {
    # builtin ciphers enabled
    if {![proj-opt-truthy cipher-aes128cbc] &&
        ![proj-opt-truthy cipher-aes256cbc] && 
        ![proj-opt-truthy cipher-chacha20] && 
        ![proj-opt-truthy cipher-sqlcipher] && 
        ![proj-opt-truthy cipher-rc4] && 
        ![proj-opt-truthy cipher-ascon128] && 
        ![proj-opt-truthy cipher-aegis]} {
      msg-result "    WARNING! All builtin ciphers explicitly disabled!"
    } {
      if {[proj-opt-truthy dynamic-ciphers]} {
        sqlite-add-feature-flag -DSQLITE3MC_HAVE_DYNAMIC_CIPHERS
        msg-result "    Dynamic ciphers enabled"
      }
    } 
    msg-result "    Builtin ciphers enabled as selected..."
  } {
    # builtin ciphers disabled
    sqlite-add-feature-flag -DSQLITE3MC_OMIT_BUILTIN_CIPHERS
    if {[proj-opt-truthy dynamic-ciphers]} {
      sqlite-add-feature-flag -DSQLITE3MC_HAVE_DYNAMIC_CIPHERS
      msg-result "    Dynamic ciphers enabled"
    } {
      msg-result "    WARNING! Neither builtin nor dynamic ciphers enabled!"
    } 
    msg-result "    Builtin ciphers enabled as selected..."
  }

  # Show the status of the builtin ciphers (enabled/disabled)
  foreach {boolFlag featureFlag ifSetEvalThis} [proj-strip-hash-comments {
    cipher-aes128cbc -DHAVE_CIPHER_AES_128_CBC {}
    cipher-aes256cbc -DHAVE_CIPHER_AES_256_CBC {}
    cipher-chacha20  -DHAVE_CIPHER_CHACHA20    {}
    cipher-sqlcipher -DHAVE_CIPHER_SQLCIPHER   {}
    cipher-rc4       -DHAVE_CIPHER_RC4         {}
    cipher-ascon128  -DHAVE_CIPHER_ASCON128    {}
    cipher-aegis     -DHAVE_CIPHER_AEGIS       {}
  }] {
    proj-if-opt-truthy $boolFlag {
      if {0 != [eval $ifSetEvalThis]} {
        msg-result "      + $boolFlag"
      }
    } {
      sqlite-add-feature-flag $featureFlag=0
      msg-result "      - $boolFlag"
    }
  }

  sqlite3mc-handle-default-cipher

  msg-result "  Additional options..."

  # Check status of column metadata
  proj-if-opt-truthy column-metadata {
    msg-result "    Column metadata enabled? yes"
    sqlite-add-feature-flag -DSQLITE_ENABLE_COLUMN_METADATA
  } {
    msg-result "    Column metadata enabled? no"
  }

  # Check status of secure delete
  proj-if-opt-truthy secure-delete {
    msg-result "    Secure Delete enabled? yes"
    sqlite-add-feature-flag -DSQLITE_SECURE_DELETE
  } {
    msg-result "    Secure Delete enabled? no"
  }

  # Check URI support
  proj-if-opt-truthy use-uri {
    msg-result "    Use URI filenames? yes"
    sqlite-add-feature-flag -DSQLITE_USE_URI
  } {
    msg-result "    Use URI filenames? no"
  }

  # Check AES hardware support
  proj-if-opt-truthy aes-hw-support {
    msg-result "    AES hardware support enabled? yes"
  } {
    msg-result "    AES hardware support enabled? no"
    sqlite-add-feature-flag -DSQLITE3MC_OMIT_AES_HARDWARE_SUPPORT
  }
}

