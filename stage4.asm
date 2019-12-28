%include "config2.asm"

        org   STAGE4_STATIC_ADDRESS

%define dd    dq
%define du    dq                            ; we are org-ed at the right address

rope:
        dq    0                             ; initial X29

%define LG(x) ___gadget %+ x

%macro dg 1
LG(G):  dd %1
%assign G G+1
%endmacro

%assign G 0

%include "rope4.asm"

        align 8
        dq    0                             ; begin pointer relocs

%assign R 0
%rep G
        dq    LG(R) - rope
%assign R R+1
%endrep
