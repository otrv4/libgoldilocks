/* Copyright (c) 2016 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "f_field.h"

void gf_mul (gf_s *__restrict__ cs, const gf as, const gf bs) {
    const uint32_t *a = as->limb, *b = bs->limb, maske = ((1<<26)-1), masko = ((1<<25)-1);
    
    uint64_t bh[9];
    int i,j;
    for (i=0; i<9; i++) bh[i] = b[i+1] * 19;
    
    uint32_t *c = cs->limb;

    uint64_t accum = 0;
    for (i=0; i<10; /*i+=2*/) {
        /* Even case. */
        for (j=0; j<i; /*j+=2*/) {
            accum += widemul(b[i-j], a[j]); j++;
            accum += widemul(2*b[i-j], a[j]); j++;
        }
        accum += widemul(b[0], a[j]); j++;
        accum += widemul(2*bh[8], a[j]); j++;
        for (; j<10; /* j+=2*/) {
            accum += widemul(bh[i-j+9], a[j]); j++;
            accum += widemul(2*bh[i-j+9], a[j]); j++;
        }
        c[i] = accum & maske;
        accum >>= 26;
        i++;

        /* Odd case is easier: all place values are exact. */
        for (j=0; j<=i; j++) {
            accum += widemul(b[i-j], a[j]);
        }
        for (; j<10; j++) {
            accum += widemul(bh[i-j+9], a[j]);
        }
        c[i] = accum & masko;
        accum >>= 25;
        i++;
    }
    
    accum *= 19;
    accum += c[0];
    c[0] = accum & maske;
    accum >>= 26;
    
    assert(accum < masko);
    c[1] += accum;
}

void gf_mulw (gf_s *__restrict__ cs, const gf as, uint64_t b) {
    const uint32_t *a = as->limb, maske = ((1<<26)-1), masko = ((1<<25)-1);
    uint32_t blo = b & maske, bhi = b>>26, bhi2 = 2*bhi;
    uint32_t *c = cs->limb;
    uint64_t accum = 0;

    accum = widemul(blo, a[0]) + widemul(bhi*38,a[9]);
    c[0] = accum & maske;
    accum >>= 26;

    accum += widemul(blo, a[1]) + widemul(bhi,a[0]);
    c[1] = accum & masko;
    accum >>= 25;

    for (int i=2; i<10; /*i+=2*/) {
        accum += widemul(blo, a[i]) + widemul(bhi2, a[i-1]);
        c[i] = accum & maske;
        accum >>= 26;
        i++;

        accum += widemul(blo, a[i]) + widemul(bhi, a[i-1]);
        c[i] = accum & masko;
        accum >>= 25;
        i++;
    }
    
    accum *= 19;
    accum += c[0];
    c[0] = accum & maske;
    accum >>= 26;
    
    assert(accum < masko);
    c[1] += accum;
}

void gf_sqr (gf_s *__restrict__ cs, const gf as) {
    gf_mul(cs,as,as); // PERF
}

void gf_strong_reduce (gf a) {
    uint32_t maske = (1<<26)-1, masko = (1<<25)-1;

    /* first, clear high */
    a->limb[0] += (a->limb[9]>>25)*19;
    a->limb[9] &= masko;

    /* now the total is less than 2p */

    /* compute total_value - p.  No need to reduce mod p. */
    int64_t scarry = 0;
    int i;
    for (i=0; i<10; /*i+=2*/) {
        scarry = scarry + a->limb[i] - ((i==0)?maske-18:maske);
        a->limb[i] = scarry & maske;
        scarry >>= 26;
        i++;

        scarry = scarry + a->limb[i] - masko;
        a->limb[i] = scarry & masko;
        scarry >>= 25;
        i++;
    }

    /* uncommon case: it was >= p, so now scarry = 0 and this = x
     * common case: it was < p, so now scarry = -1 and this = x - p + 2^255
     * so let's add back in p.  will carry back off the top for 2^255.
     */

    assert(word_is_zero(scarry) | word_is_zero(scarry+1));

    uint32_t scarry_masko = scarry & masko, scarry_maske = scarry & maske;
    uint64_t carry = 0;

    /* add it back */
    for (i=0; i<10; /*i+=2*/) {
        carry = carry + a->limb[i] + ((i==0)?(scarry_maske&~18):scarry_maske);
        a->limb[i] = carry & maske;
        carry >>= 26;
        i++;

        carry = carry + a->limb[i] + scarry_masko;
        a->limb[i] = carry & masko;
        carry >>= 25;
        i++;
    }

    assert(word_is_zero(carry + scarry));
}

#define LIMB_PLACE_VALUE(i) (((i)&1)?25:26)
void gf_serialize (uint8_t serial[32], const gf x) {
    gf red;
    gf_copy(red, x);
    gf_strong_reduce(red);
    unsigned int j=0, fill=0;
    dword_t buffer = 0;
    for (unsigned int i=0; i<32; i++) {
        if (fill < 8 && j < sizeof(red->limb)/sizeof(red->limb[0])) {
            buffer |= ((dword_t)red->limb[j]) << fill;
            fill += LIMB_PLACE_VALUE(j);
            j++;
        }
        serial[i] = buffer;
        fill -= 8;
        buffer >>= 8;
    }
}

mask_t gf_deserialize (gf x, const uint8_t serial[32]) {
    unsigned int j=0, fill=0;
    dword_t buffer = 0;
    for (unsigned int i=0; i<32; i++) {
        buffer |= ((dword_t)serial[i]) << fill;
        fill += 8;
        if (fill >= LIMB_PLACE_VALUE(j) || i == 31) {
            assert(j < sizeof(x->limb)/sizeof(x->limb[0]));
            word_t mask = ((1ull)<<LIMB_PLACE_VALUE(j))-1;
            x->limb[j] = (i==31) ? buffer : (buffer & mask); // FIXME: this can in theory truncate the buffer if it's not in field.
            buffer >>= LIMB_PLACE_VALUE(j);
            fill -= LIMB_PLACE_VALUE(j);
            j++;
        }
    }
    return -1; // FIXME: test whether in field.
}
