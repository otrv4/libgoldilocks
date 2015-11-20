/**
 * @file field.h
 * @brief Generic gf header.
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 */

#ifndef __GF_H__
#define __GF_H__

#include "constant_time.h"
#include "f_field.h"
#include <string.h>

/**
 * Returns 1/sqrt(+- x).
 * 
 * The Legendre symbol of the result is the same as that of the
 * input.
 * 
 * If x=0, returns 0.
 */
void gf_isr(gf a, const gf x);
    
/**
 * Square x, n times.
 */
static INLINE UNUSED void
gf_sqrn (
    gf_s *__restrict__ y,
    const gf x,
    int n
) {
    gf tmp;
    assert(n>0);
    if (n&1) {
        gf_sqr(y,x);
        n--;
    } else {
        gf_sqr(tmp,x);
        gf_sqr(y,tmp);
        n-=2;
    }
    for (; n; n-=2) {
        gf_sqr(tmp,y);
        gf_sqr(y,tmp);
    }
}

static __inline__ void
gf_sub (
    gf d,
    const gf a,
    const gf b
) {
    gf_sub_RAW ( d, a, b );
    gf_bias( d, 2 );
    gf_weak_reduce ( d );
}

static __inline__ void
gf_add (
    gf d,
    const gf a,
    const gf b
) {
    gf_add_RAW ( d, a, b );
    gf_weak_reduce ( d );
}

#define gf_add_nr gf_add_RAW

/** Subtract mod p.  Bias by 2 and don't reduce  */
static inline void gf_sub_nr ( gf c, const gf a, const gf b ) {
//    FOR_LIMB_U(i, c->limb[i] = a->limb[i] - b->limb[i] + 2*P->limb[i] );
    gf_sub_RAW(c,a,b);
    gf_bias(c, 2);
    if (DECAF_WORD_BITS==32) gf_weak_reduce(c); // HACK
}

/** Subtract mod p. Bias by amt but don't reduce.  */
static inline void gf_subx_nr ( gf c, const gf a, const gf b, int amt ) {
    gf_sub_RAW(c,a,b);
    gf_bias(c, amt);
    if (DECAF_WORD_BITS==32) gf_weak_reduce(c); // HACK
}


#endif // __GF_H__
