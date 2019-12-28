#include "config.h"

extern access;
extern close;
extern creat;
extern exit [[noreturn]];
extern unlink;

#define	F_OK		0	/* test for existence of file */

if !([[stack=0x200]]access(STAGE4_FLAG, F_OK)) goto done;
close(creat(STAGE4_FLAG, 420));

done:
unlink(STAGE4_NAME);
exit(42);
