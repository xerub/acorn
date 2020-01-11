// adjust these values in case of emergency

#define RACOON_SANDBOX

#define FAKE_SHARED_CACHE_ADDR	0x140000000

#ifdef RACOON_SANDBOX
#define STAGE2_NAME		"/etc/racoon/s2"
#define STAGE5_NAME		"/etc/racoon/stage5.bin"
#define STAGE6_NAME		"/etc/racoon/stage6.js"
//#define STAGE2_NAME		"/var/root/stg2"
//#define STAGE5_NAME		"/var/root/stage5.bin"
//#define STAGE6_NAME		"/var/root/stage6.js"
#else
#define STAGE2_NAME		"/tmp/stage2.bin"
#define STAGE5_NAME		"/tmp/stage5.bin"
#define STAGE6_NAME		"/tmp/stage6.js"
#endif
#define STAGE2_MAX_SIZE		0x30000
#define STAGE2_STATIC_ADDRESS	(FAKE_SHARED_CACHE_ADDR - STAGE2_MAX_SIZE)

#define STAGE3_FAKE_OBJECT_SZ	0x100

#ifdef RACOON_SANDBOX
#define STAGE4_NAME		"/var/run/racoon.pid"
#else
#define STAGE4_NAME		"/tmp/stage4.bin"
#endif
#define STAGE4_MAX_SIZE		0x10000
#define STAGE4_STATIC_ADDRESS	0x17FFF0000

#define STAGE4_FLAG		"/tmp/flag"

#define SHARED_CACHE_NAME	"/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
