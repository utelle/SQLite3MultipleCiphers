
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# If using SEE, uncomment the following:
LOCAL_CFLAGS += -DSQLITE_HAS_CODEC

#Define HAVE_USLEEP, otherwise ALL sleep() calls take at least 1000ms
LOCAL_CFLAGS += -DHAVE_USLEEP=1

# Enable SQLite extensions.
LOCAL_CFLAGS += -DSQLITE_ENABLE_FTS5 
LOCAL_CFLAGS += -DSQLITE_ENABLE_RTREE
LOCAL_CFLAGS += -DSQLITE_ENABLE_FTS3
LOCAL_CFLAGS += -DSQLITE_ENABLE_BATCH_ATOMIC_WRITE

# Select default encryption scheme
# ChaCha20-Poly1305 is the default
# Uncomment the following, if a different scheme should be selected
#LOCAL_CFLAGS += -DCODEC_TYPE=CODEC_TYPE_CHACHA20

# Set max number of attached databases
# Uncomment and modify the following, if a non-default number should be used
#LOCAL_CFLAGS += -DSQLITE_MAX_ATTACHED=10

# Enable SQLite3MC settings
LOCAL_CFLAGS += -DSQLITE_SECURE_DELETE=1
LOCAL_CFLAGS += -DSQLITE_DQS=0
LOCAL_CFLAGS += -DSQLITE_SOUNDEX=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_COLUMN_METADATA=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_DESERIALIZE=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_FTS3_PARENTHESIS=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_FTS4=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_GEOPOLY=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_EXTFUNC=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_MATH_FUNCTIONS=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_CSV=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_VSV=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_SHA3=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_CARRAY=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_PERCENTILE=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_FILEIO=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_SERIES=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_UUID=1
LOCAL_CFLAGS += -DSQLITE_ENABLE_REGEXP=1
LOCAL_CFLAGS += -DSQLITE_USER_AUTHENTICATION=0

# This is important - it causes SQLite to use memory for temp files. Since 
# Android has no globally writable temp directory, if this is not defined the
# application throws an exception when it tries to create a temp file.
#
LOCAL_CFLAGS += -DSQLITE_TEMP_STORE=3

LOCAL_CFLAGS += -DHAVE_CONFIG_H -DKHTML_NO_EXCEPTIONS -DGKWQ_NO_JAVA
LOCAL_CFLAGS += -DNO_SUPPORT_JS_BINDING -DQT_NO_WHEELEVENT -DKHTML_NO_XBL
LOCAL_CFLAGS += -U__APPLE__
LOCAL_CFLAGS += -DHAVE_STRCHRNUL=0
LOCAL_CFLAGS += -DSQLITE_USE_URI=1
LOCAL_CFLAGS += -Wno-unused-parameter -Wno-int-to-pointer-cast
LOCAL_CFLAGS += -Wno-uninitialized -Wno-parentheses
#LOCAL__CFLAGS += -std=c99
LOCAL_CPPFLAGS += -Wno-conversion-null


ifeq ($(TARGET_ARCH), x86)
    LOCAL_CFLAGS += -DPACKED=""
    LOCAL_CFLAGS += -maes -msse4.2
else
    LOCAL_CFLAGS += -DPACKED="__attribute__ ((packed))"
endif

LOCAL_SRC_FILES:=                             \
	android_database_SQLiteCommon.cpp     \
	android_database_SQLiteConnection.cpp \
	android_database_SQLiteGlobal.cpp     \
	android_database_SQLiteDebug.cpp      \
	JNIHelp.cpp JniConstants.cpp

LOCAL_SRC_FILES += sqlite3.c

LOCAL_C_INCLUDES += $(LOCAL_PATH) $(LOCAL_PATH)/nativehelper/

LOCAL_MODULE:= libsqliteX
LOCAL_LDLIBS += -ldl -llog 

include $(BUILD_SHARED_LIBRARY)

