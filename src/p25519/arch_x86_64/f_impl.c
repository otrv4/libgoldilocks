/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "f_field.h"

void gf_mul (gf_s *__restrict__ cs, const gf as, const gf bs) {
    const uint64_t *a = as->limb, *b = bs->limb, mask = ((1ull<<51)-1);
    uint64_t *c = cs->limb;
    
    __uint128_t accum0, accum1, accum2;
    
    uint64_t ai = a[0];
    accum0 = widemul_rm(ai, &b[0]);
    accum1 = widemul_rm(ai, &b[1]);
    accum2 = widemul_rm(ai, &b[2]);
    
    ai = a[1];
    mac_rm(&accum2, ai, &b[1]);
    mac_rm(&accum1, ai, &b[0]);
    ai *= 19;
    mac_rm(&accum0, ai, &b[4]);
    
    ai = a[2];
    mac_rm(&accum2, ai, &b[0]);
    ai *= 19;
    mac_rm(&accum0, ai, &b[3]);
    mac_rm(&accum1, ai, &b[4]);
    
    ai = a[3] * 19;
    mac_rm(&accum0, ai, &b[2]);
    mac_rm(&accum1, ai, &b[3]);
    mac_rm(&accum2, ai, &b[4]);
    
    ai = a[4] * 19;
    mac_rm(&accum0, ai, &b[1]);
    mac_rm(&accum1, ai, &b[2]);
    mac_rm(&accum2, ai, &b[3]);
    
    uint64_t c0 = accum0 & mask;
    accum1 += shrld(accum0, 51);
    uint64_t c1 = accum1 & mask;
    accum2 += shrld(accum1, 51);
    c[2] = accum2 & mask;
    
    accum0 = shrld(accum2, 51);

    mac_rm(&accum0, ai, &b[4]);
    
    ai = a[0];
    mac_rm(&accum0, ai, &b[3]);
    accum1 = widemul_rm(ai, &b[4]);
    
    ai = a[1];
    mac_rm(&accum0, ai, &b[2]);
    mac_rm(&accum1, ai, &b[3]);
    
    ai = a[2];
    mac_rm(&accum0, ai, &b[1]);
    mac_rm(&accum1, ai, &b[2]);
    
    ai = a[3];
    mac_rm(&accum0, ai, &b[0]);
    mac_rm(&accum1, ai, &b[1]);
    
    ai = a[4];
    mac_rm(&accum1, ai, &b[0]);
    
    c[3] = accum0 & mask;
    accum1 += shrld(accum0, 51);
    c[4] = accum1 & mask;
    
    /* 2^102 * 16 * 5 * 19 * (1+ep) >> 64
     * = 2^(-13 + <13)
     * PERF: good enough to fit into uint64_t?
     */
    
    uint64_t a1 = shrld(accum1,51);
    accum1 = (__uint128_t)a1 * 19 + c0;
    c[0] = accum1 & mask;
    c[1] = c1 + shrld(accum1,51);
}

void gf_sqr (gf_s *__restrict__ cs, const gf as) {
    const uint64_t *a = as->limb, mask = ((1ull<<51)-1);
    uint64_t *c = cs->limb;
    
    __uint128_t accum0, accum1, accum2;
    
    uint64_t ai = a[0];
    accum0 = widemul_rr(ai, ai);
    ai *= 2;
    accum1 = widemul_rm(ai, &a[1]);
    accum2 = widemul_rm(ai, &a[2]);
    
    ai = a[1];
    mac_rr(&accum2, ai, ai);
    ai *= 38;
    mac_rm(&accum0, ai, &a[4]);
    
    ai = a[2] * 38;
    mac_rm(&accum0, ai, &a[3]);
    mac_rm(&accum1, ai, &a[4]);
    
    ai = a[3] * 19;
    mac_rm(&accum1, ai, &a[3]);
    ai *= 2;
    mac_rm(&accum2, ai, &a[4]);
    
    uint64_t c0 = accum0 & mask;
    accum1 += shrld(accum0, 51);
    uint64_t c1 = accum1 & mask;
    accum2 += shrld(accum1, 51);
    c[2] = accum2 & mask;
    
    accum0 = accum2 >> 51;
    
    ai = a[0]*2;
    mac_rm(&accum0, ai, &a[3]);
    accum1 = widemul_rm(ai, &a[4]);
    
    ai = a[1]*2;
    mac_rm(&accum0, ai, &a[2]);
    mac_rm(&accum1, ai, &a[3]);
    
    mac_rr(&accum0, a[4]*19, a[4]);
    mac_rr(&accum1, a[2], a[2]);
    
    c[3] = accum0 & mask;
    accum1 += shrld(accum0, 51);
    c[4] = accum1 & mask;
    
    /* 2^102 * 16 * 5 * 19 * (1+ep) >> 64
     * = 2^(-13 + <13)
     * PERF: good enough to fit into uint64_t?
     */
    
    uint64_t a1 = shrld(accum1,51);
    accum1 = (__uint128_t)a1 * 19 + c0;
    c[0] = accum1 & mask;
    c[1] = c1 + shrld(accum1,51);
}

void gf_mulw (gf_s *__restrict__ cs, const gf as, uint64_t b) {
    const uint64_t *a = as->limb, mask = ((1ull<<51)-1);
    uint64_t *c = cs->limb;

    __uint128_t accum = widemul_rm(b, &a[0]);
    uint64_t c0 = accum & mask;
    accum = shrld(accum,51);
    
    mac_rm(&accum, b, &a[1]);
    uint64_t c1 = accum & mask;
    accum = shrld(accum,51);
    
    mac_rm(&accum, b, &a[2]);
    c[2] = accum & mask;
    accum = shrld(accum,51);
    
    mac_rm(&accum, b, &a[3]);
    c[3] = accum & mask;
    accum = shrld(accum,51);
    
    mac_rm(&accum, b, &a[4]);
    c[4] = accum & mask;

    accum = shrld(accum,51);
    accum = accum * 19 + c0;
    
    c[0] = accum & mask;
    c[1] = c1 + shrld(accum,51);
}

void gf_strong_reduce (gf a) {
    uint64_t mask = (1ull<<51)-1;

    /* first, clear high */
    a->limb[0] += (a->limb[4]>>51)*19;
    a->limb[4] &= mask;

    /* now the total is less than 2p */

    /* compute total_value - p.  No need to reduce mod p. */
    __int128_t scarry = 0;
    int i;
    for (i=0; i<5; i++) {
        scarry = scarry + a->limb[i] - ((i==0)?mask-18:mask);
        a->limb[i] = scarry & mask;
        scarry >>= 51;
    }

    /* uncommon case: it was >= p, so now scarry = 0 and this = x
    * common case: it was < p, so now scarry = -1 and this = x - p + 2^255
    * so let's add back in p.  will carry back off the top for 2^255.
    */

    assert(word_is_zero(scarry) | word_is_zero(scarry+1));

    uint64_t scarry_mask = scarry & mask;
    __uint128_t carry = 0;

    /* add it back */
    for (i=0; i<5; i++) {
        carry = carry + a->limb[i] + ((i==0)?(scarry_mask&~18):scarry_mask);
        a->limb[i] = carry & mask;
        carry >>= 51;
    }

    assert(word_is_zero(carry + scarry));
}
