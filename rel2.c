;// `rope` was defined outside us (in header) and so is `rope_end`
;// our caller stashed the slide in the first word, that is `rope`
;// relocations start with a 0 and are relative to `rope`

stash = &rope;
slide = *stash;
cur2 = &rope_end;
rel2_loop:
    cur2 = cur2 - 8;
    off2 = *cur2;
    ptr2_dst = ptr2_src = &rope + off2;
    *ptr2_dst = *ptr2_src + slide;
    if (off2) goto rel2_loop; // XXX this construct will add an extra slide to offset=0, but ok
