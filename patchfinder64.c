//
//  patchfinder64.c
//  extra_recipe
//
//  Created by xerub on 06/06/2017.
//  Copyright © 2017 xerub. All rights reserved.
//

#include <assert.h>
#include <stdint.h>
#include <string.h>

typedef unsigned long long addr_t;

#define IS64(image) (*(uint8_t *)(image) & 1)

#define MACHO(p) ((*(unsigned int *)(p) & ~1) == 0xfeedface)

/* generic stuff *************************************************************/

#define UCHAR_MAX 255

static unsigned char *
boyermoore_horspool_memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen)
{
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */

    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;

    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;

    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;

    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;

    /* ---- Do the matching ---- */

    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return (void *)haystack;

        /* otherwise, we need to skip some bytes and start again.
           Note that here we are getting the skip value based on the last byte
           of needle, no matter where we didn't match. So if needle is: "abcd"
           then we are skipping based on 'd' and that value will be 4, and
           for "abcdd" we again skip on 'd' but the value will be only 1.
           The alternative of pretending that the mismatched character was
           the last character is slower in the normal case (E.g. finding
           "abcd" in "...azcd..." gives 4 by using 'd' but only
           4-2==2 using 'z'. */
        hlen     -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }

    return NULL;
}

/* disassembler **************************************************************/

static int HighestSetBit(int N, uint32_t imm)
{
	int i;
	for (i = N - 1; i >= 0; i--) {
		if (imm & (1 << i)) {
			return i;
		}
	}
	return -1;
}

static uint64_t ZeroExtendOnes(unsigned M, unsigned N)	// zero extend M ones to N width
{
	(void)N;
	return ((uint64_t)1 << M) - 1;
}

static uint64_t RORZeroExtendOnes(unsigned M, unsigned N, unsigned R)
{
	uint64_t val = ZeroExtendOnes(M, N);
	if (R == 0) {
		return val;
	}
	return ((val >> R) & (((uint64_t)1 << (N - R)) - 1)) | ((val & (((uint64_t)1 << R) - 1)) << (N - R));
}

static uint64_t Replicate(uint64_t val, unsigned bits)
{
	uint64_t ret = val;
	unsigned shift;
	for (shift = bits; shift < 64; shift += bits) {	// XXX actually, it is either 32 or 64
		ret |= (val << shift);
	}
	return ret;
}

static int DecodeBitMasks(unsigned immN, unsigned imms, unsigned immr, int immediate, uint64_t *newval)
{
	unsigned levels, S, R, esize;
	int len = HighestSetBit(7, (immN << 6) | (~imms & 0x3F));
	if (len < 1) {
		return -1;
	}
	levels = ZeroExtendOnes(len, 6);
	if (immediate && (imms & levels) == levels) {
		return -1;
	}
	S = imms & levels;
	R = immr & levels;
	esize = 1 << len;
	*newval = Replicate(RORZeroExtendOnes(S + 1, esize, R), esize);
	return 0;
}

static int DecodeMov(uint32_t opcode, uint64_t total, int first, uint64_t *newval)
{
	unsigned o = (opcode >> 29) & 3;
	unsigned k = (opcode >> 23) & 0x3F;
	unsigned rn, rd;
	uint64_t i;

	if (k == 0x24 && o == 1) {			// MOV (bitmask imm) <=> ORR (immediate)
		unsigned s = (opcode >> 31) & 1;
		unsigned N = (opcode >> 22) & 1;
		if (s == 0 && N != 0) {
			return -1;
		}
		rn = (opcode >> 5) & 0x1F;
		if (rn == 31) {
			unsigned imms = (opcode >> 10) & 0x3F;
			unsigned immr = (opcode >> 16) & 0x3F;
			return DecodeBitMasks(N, imms, immr, 1, newval);
		}
	} else if (k == 0x25) {				// MOVN/MOVZ/MOVK
		unsigned s = (opcode >> 31) & 1;
		unsigned h = (opcode >> 21) & 3;
		if (s == 0 && h > 1) {
			return -1;
		}
		i = (opcode >> 5) & 0xFFFF;
		h *= 16;
		i <<= h;
		if (o == 0) {				// MOVN
			*newval = ~i;
			return 0;
		} else if (o == 2) {			// MOVZ
			*newval = i;
			return 0;
		} else if (o == 3 && !first) {		// MOVK
			*newval = (total & ~((uint64_t)0xFFFF << h)) | i;
			return 0;
		}
	} else if ((k | 1) == 0x23 && !first) {		// ADD (immediate)
		unsigned h = (opcode >> 22) & 3;
		if (h > 1) {
			return -1;
		}
		rd = opcode & 0x1F;
		rn = (opcode >> 5) & 0x1F;
		if (rd != rn) {
			return -1;
		}
		i = (opcode >> 10) & 0xFFF;
		h *= 12;
		i <<= h;
		if (o & 2) {				// SUB
			*newval = total - i;
			return 0;
		} else {				// ADD
			*newval = total + i;
			return 0;
		}
	}

	return -1;
}

/* patchfinder ***************************************************************/

static addr_t
step64(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start + length;
    while (start < end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start += 4;
    }
    return 0;
}

static addr_t
step64_back(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start - length;
    while (start >= end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start -= 4;
    }
    return 0;
}

static addr_t
bof64(const uint8_t *buf, addr_t start, addr_t where)
{
    for (; where >= start; where -= 4) {
        uint32_t op = *(uint32_t *)(buf + where);
        if ((op & 0xFFC003FF) == 0x910003FD) {
            unsigned delta = (op >> 10) & 0xFFF;
            //printf("%x: ADD X29, SP, #0x%x\n", where, delta);
            if ((delta & 0xF) == 0) {
                addr_t prev = where - ((delta >> 4) + 1) * 4;
                uint32_t au = *(uint32_t *)(buf + prev);
                if ((au & 0xFFC003E0) == 0xA98003E0) {
                    //printf("%x: STP x, y, [SP,#-imm]!\n", prev);
                    return prev;
                }
                // try something else
                while (where > start) {
                    where -= 4;
                    au = *(uint32_t *)(buf + where);
                    // SUB SP, SP, #imm
                    if ((au & 0xFFC003FF) == 0xD10003FF && ((au >> 10) & 0xFFF) == delta + 0x10) {
                        return where;
                    }
                    // STP x, y, [SP,#imm]
                    if ((au & 0xFFC003E0) != 0xA90003E0) {
                        where += 4;
                        break;
                    }
                }
            }
        }
    }
    return 0;
}

static addr_t
xref64(const uint8_t *buf, addr_t start, addr_t end, addr_t what)
{
    addr_t i;
    uint64_t value[32];

    memset(value, 0, sizeof(value));

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            continue;				// XXX should not XREF on its own?
        /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
            unsigned rd = op & 0x1F;
            unsigned rm = (op >> 16) & 0x1F;
            //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
            value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        /*} else if ((op & 0xF9C00000) == 0xF9000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[rn] = value[rn] + imm;	// XXX address, not actual value*/
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;		// XXX address, not actual value
        }
        if (value[reg] == what) {
            return i;
        }
    }
    return 0;
}

static addr_t
calc64(const uint8_t *buf, addr_t start, addr_t end, int which)
{
    addr_t i;
    uint64_t value[32];

    memset(value, 0, sizeof(value));

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
        /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
            unsigned rd = op & 0x1F;
            unsigned rm = (op >> 16) & 0x1F;
            //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
            value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        } else if ((op & 0xF9C00000) == 0xB9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 2;
            //printf("%llx: LDR W%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        } else if ((op & 0xF9C00000) == 0xF9000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        } else if ((op & 0xF9C00000) == 0xB9000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 2;
            //printf("%llx: STR W%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;		// XXX address, not actual value
        }
    }
    return value[which];
}

static addr_t
calc64mov(const uint8_t *buf, addr_t start, addr_t end, int which)
{
    addr_t i;
    uint64_t value[32];

    memset(value, 0, sizeof(value));

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        uint64_t newval;
        int rv = DecodeMov(op, value[reg], 0, &newval);
        if (rv == 0) {
            if (((op >> 31) & 1) == 0) {
                newval &= 0xFFFFFFFF;
            }
            value[reg] = newval;
        }
    }
    return value[which];
}

static addr_t
find_call64(const uint8_t *buf, addr_t start, size_t length)
{
    return step64(buf, start, length, 0x94000000, 0xFC000000);
}

static addr_t
follow_call64(const uint8_t *buf, addr_t call)
{
    long long w;
    w = *(uint32_t *)(buf + call) & 0x3FFFFFF;
    w <<= 64 - 26;
    w >>= 64 - 26 - 2;
    return call + w;
}

static addr_t
follow_cbz(const uint8_t *buf, addr_t cbz)
{
    return cbz + ((*(int *)(buf + cbz) & 0x3FFFFE0) << 10 >> 13);
}

static addr_t
xref64code(const uint8_t *buf, addr_t start, addr_t end, addr_t what)
{
    addr_t i;

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        if ((op & 0x7C000000) == 0x14000000) {
            addr_t where = follow_call64(buf, i);
            //printf("%llx: B[L] 0x%llx\n", i + kerndumpbase, kerndumpbase + where);
            if (where == what) {
                return i;
            }
        }
    }
    return 0;
}

#define INSN_RET  0xD65F03C0, 0xFFFFFFFF
#define INSN_CALL 0x94000000, 0xFC000000
#define INSN_B    0x14000000, 0xFC000000
#define INSN_CBZ  0x34000000, 0xFC000000
#define INSN_BLR  0xD63F0000, 0xFFFFFC1F
