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
    
/** Square x, n times. */
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

#define gf_add_nr gf_add_RAW

/** Subtract mod p.  Bias by 2 and don't reduce  */
static inline void gf_sub_nr ( gf c, const gf a, const gf b ) {
    gf_sub_RAW(c,a,b);
    gf_bias(c, 2);
    if (DECAF_WORD_BITS==32) gf_weak_reduce(c); // HACK PERF MAGIC
    // Depending on headroom, this is needed in some of the Ed routines, but
    // not in the Montgomery ladder.  Need to find a better way to prevent
    // overflow.  In particular, the headroom depends on the field+arch combo,
    // not just one or the other, and whether the reduction is needed depends
    // also on the algorithm.
}

/** Subtract mod p. Bias by amt but don't reduce.  */
static inline void gf_subx_nr ( gf c, const gf a, const gf b, int amt ) {
    gf_sub_RAW(c,a,b);
    gf_bias(c, amt);
    if (DECAF_WORD_BITS==32) gf_weak_reduce(c); // HACK PERF MAGIC
}


#endif // __GF_H__
