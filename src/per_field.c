/**
 * @cond internal
 * @file decaf_crypto.c
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Generic arithmetic which has to be compiled per field.
 */

#include "field.h"

const gf ZERO = {{{0}}}, ONE = {{{ [LIMBPERM(0)] = 1 }}};

/** Serialize to wire format. */
void gf_serialize (uint8_t serial[SER_BYTES], const gf x) {
    gf red;
    gf_copy(red, x);
    gf_strong_reduce(red);
    
    unsigned int j=0, fill=0;
    dword_t buffer = 0;
    UNROLL for (unsigned int i=0; i<SER_BYTES; i++) {
        if (fill < 8 && j < NLIMBS) {
            buffer |= ((dword_t)red->limb[LIMBPERM(j)]) << fill;
            fill += LIMB_PLACE_VALUE(LIMBPERM(j));
            j++;
        }
        serial[i] = buffer;
        fill -= 8;
        buffer >>= 8;
    }
}

/** Deserialize from wire format; return -1 on success and 0 on failure. */
mask_t gf_deserialize (gf x, const uint8_t serial[SER_BYTES]) {
    unsigned int j=0, fill=0;
    dword_t buffer = 0;
    dsword_t scarry = 0;
    UNROLL for (unsigned int i=0; i<NLIMBS; i++) {
        UNROLL while (fill < LIMB_PLACE_VALUE(LIMBPERM(i)) && j < SER_BYTES) {
            buffer |= ((dword_t)serial[j]) << fill;
            fill += 8;
            j++;
        }
        x->limb[LIMBPERM(i)] = (i<NLIMBS-1) ? buffer & LIMB_MASK(LIMBPERM(i)) : buffer;
        fill -= LIMB_PLACE_VALUE(LIMBPERM(i));
        buffer >>= LIMB_PLACE_VALUE(LIMBPERM(i));
        scarry = (scarry + x->limb[LIMBPERM(i)] - MODULUS->limb[LIMBPERM(i)]) >> (8*sizeof(word_t));
    }
    return word_is_zero(buffer) & ~word_is_zero(scarry);
}

/** Reduce to canonical form. */
void gf_strong_reduce (gf a) {
    /* first, clear high */
    gf_weak_reduce(a); /* Determined to have negligible perf impact. */

    /* now the total is less than 2p */

    /* compute total_value - p.  No need to reduce mod p. */
    dsword_t scarry = 0;
    for (unsigned int i=0; i<NLIMBS; i++) {
        scarry = scarry + a->limb[LIMBPERM(i)] - MODULUS->limb[LIMBPERM(i)];
        a->limb[LIMBPERM(i)] = scarry & LIMB_MASK(LIMBPERM(i));
        scarry >>= LIMB_PLACE_VALUE(LIMBPERM(i));
    }

    /* uncommon case: it was >= p, so now scarry = 0 and this = x
     * common case: it was < p, so now scarry = -1 and this = x - p + 2^255
     * so let's add back in p.  will carry back off the top for 2^255.
     */
    assert(word_is_zero(scarry) | word_is_zero(scarry+1));

    word_t scarry_0 = scarry;
    dword_t carry = 0;

    /* add it back */
    for (unsigned int i=0; i<NLIMBS; i++) {
        carry = carry + a->limb[LIMBPERM(i)] + (scarry_0 & MODULUS->limb[LIMBPERM(i)]);
        a->limb[LIMBPERM(i)] = carry & LIMB_MASK(LIMBPERM(i));
        carry >>= LIMB_PLACE_VALUE(LIMBPERM(i));
    }

    assert(word_is_zero(carry + scarry_0));
}

/** Compare a==b */
mask_t gf_eq(const gf a, const gf b) {
    gf c;
    gf_sub(c,a,b);
    gf_strong_reduce(c);
    mask_t ret=0;
    for (unsigned int i=0; i<NLIMBS; i++) {
        ret |= c->limb[LIMBPERM(i)];
    }

    return word_is_zero(ret);
}
