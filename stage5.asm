%define dd    dq

rope:
        dq    0                             ; initial X29

%define LG(x) ___gadget %+ x
%define LU(x) ___ulocal %+ x

%macro dg 1
LG(G):  dd %1
%assign G G+1
%endmacro

%macro du 1
LU(U):  dd %1
%assign U U+1
%endmacro

%assign G 0
%assign U 0

%include "rope5.asm"

        align 8
        dq    0                             ; begin pointer relocs

%assign R 0
%rep U
        dq    LU(R) - rope
%assign R R+1
%endrep

        align 8
        dq    0                             ; begin pointer relocs

%assign R 0
%rep G
        dq    LG(R) - rope
%assign R R+1
%endrep
