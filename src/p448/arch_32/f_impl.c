/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "f_field.h"

void gf_mul (gf_s *__restrict__ cs, const gf as, const gf bs) { 
    const uint32_t *a = as->limb, *b = bs->limb;
    uint32_t *c = cs->limb;

    uint64_t accum0 = 0, accum1 = 0, accum2 = 0;
    uint32_t mask = (1<<28) - 1;  

    uint32_t aa[8], bb[8];
    
    int i,j;
    for (i=0; i<8; i++) {
        aa[i] = a[i] + a[i+8];
        bb[i] = b[i] + b[i+8];
    }
    
    for (j=0; j<8; j++) {
        accum2 = 0;
    
        for (i=0; i<=j; i++) {      
            accum2 += widemul(a[j-i],b[i]);
            accum1 += widemul(aa[j-i],bb[i]);
            accum0 += widemul(a[8+j-i], b[8+i]);
        }
        
        accum1 -= accum2;
        accum0 += accum2;
        accum2 = 0;
        
        for (; i<8; i++) {
            accum0 -= widemul(a[8+j-i], b[i]);
            accum2 += widemul(aa[8+j-i], bb[i]);
            accum1 += widemul(a[16+j-i], b[8+i]);
        }

        accum1 += accum2;
        accum0 += accum2;

        c[j] = ((uint32_t)(accum0)) & mask;
        c[j+8] = ((uint32_t)(accum1)) & mask;

        accum0 >>= 28;
        accum1 >>= 28;
    }
    
    accum0 += accum1;
    accum0 += c[8];
    accum1 += c[0];
    c[8] = ((uint32_t)(accum0)) & mask;
    c[0] = ((uint32_t)(accum1)) & mask;
    
    accum0 >>= 28;
    accum1 >>= 28;
    c[9] += ((uint32_t)(accum0));
    c[1] += ((uint32_t)(accum1));
}

void gf_mulw (gf_s *__restrict__ cs, const gf as, uint64_t b) {
    const uint32_t bhi = b>>28, blo = b & ((1<<28)-1);
    
    const uint32_t *a = as->limb;
    uint32_t *c = cs->limb;

    uint64_t accum0, accum8;
    uint32_t mask = (1ull<<28)-1;  

    int i;

    accum0 = widemul(blo, a[0]);
    accum8 = widemul(blo, a[8]);
    accum0 += widemul(bhi, a[15]);
    accum8 += widemul(bhi, a[15] + a[7]);

    c[0] = accum0 & mask; accum0 >>= 28;
    c[8] = accum8 & mask; accum8 >>= 28;
    
    for (i=1; i<8; i++) {
        accum0 += widemul(blo, a[i]);
        accum8 += widemul(blo, a[i+8]);
        
        accum0 += widemul(bhi, a[i-1]);
        accum8 += widemul(bhi, a[i+7]);

        c[i] = accum0 & mask; accum0 >>= 28;
        c[i+8] = accum8 & mask; accum8 >>= 28;
    }

    accum0 += accum8 + c[8];
    c[8] = accum0 & mask;
    c[9] += accum0 >> 28;

    accum8 += c[0];
    c[0] = accum8 & mask;
    c[1] += accum8 >> 28;
}

void gf_sqr (gf_s *__restrict__ cs, const gf as) {
    gf_mul(cs,as,as); /* PERF */
}

void gf_strong_reduce (gf a) {
    word_t mask = (1ull<<28)-1;

    /* first, clear high */
    a->limb[8] += a->limb[15]>>28;
    a->limb[0] += a->limb[15]>>28;
    a->limb[15] &= mask;

    /* now the total is less than 2^448 - 2^(448-56) + 2^(448-56+8) < 2p */

    /* compute total_value - p.  No need to reduce mod p. */

    dsword_t scarry = 0;
    int i;
    for (i=0; i<16; i++) {
        scarry = scarry + a->limb[i] - ((i==8)?mask-1:mask);
        a->limb[i] = scarry & mask;
        scarry >>= 28;
    }

    /* uncommon case: it was >= p, so now scarry = 0 and this = x
    * common case: it was < p, so now scarry = -1 and this = x - p + 2^448
    * so let's add back in p.  will carry back off the top for 2^448.
    */

    assert(word_is_zero(scarry) | word_is_zero(scarry+1));

    word_t scarry_mask = scarry & mask;
    dword_t carry = 0;

    /* add it back */
    for (i=0; i<16; i++) {
        carry = carry + a->limb[i] + ((i==8)?(scarry_mask&~1):scarry_mask);
        a->limb[i] = carry & mask;
        carry >>= 28;
    }

    assert(word_is_zero(carry + scarry));
}
