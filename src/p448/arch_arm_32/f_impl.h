/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P448_H__
#define __P448_H__ 1

#include "f_field.h"

#include <stdint.h>
#include <assert.h>

#define LIMB(x) (x##ull)&((1ull<<28)-1), (x##ull)>>28
#define FIELD_LITERAL(a,b,c,d,e,f,g,h) \
    {{LIMB(a),LIMB(b),LIMB(c),LIMB(d),LIMB(e),LIMB(f),LIMB(g),LIMB(h)}}

#ifdef __cplusplus
extern "C" {
#endif

/* -------------- Inline functions begin here -------------- */

void gf_add_RAW (gf out, const gf a, const gf b) {
    for (unsigned int i=0; i<sizeof(*out)/sizeof(uint32xn_t); i++) {
        ((uint32xn_t*)out)[i] = ((const uint32xn_t*)a)[i] + ((const uint32xn_t*)b)[i];
    }
    /*
    for (unsigned int i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
    */
}

void gf_sub_RAW (gf out, const gf a, const gf b) {
    for (unsigned int i=0; i<sizeof(*out)/sizeof(uint32xn_t); i++) {
        ((uint32xn_t*)out)[i] = ((const uint32xn_t*)a)[i] - ((const uint32xn_t*)b)[i];
    }
    /*
    for (unsigned int i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] - b->limb[i];
    }
    */
}

void gf_bias (gf a, int amt) {
    uint32_t co1 = ((1ull<<28)-1)*amt, co2 = co1-amt;
    uint32x4_t lo = {co1,co1,co1,co1}, hi = {co2,co1,co1,co1};
    uint32x4_t *aa = (uint32x4_t*) a;
    aa[0] += lo;
    aa[1] += lo;
    aa[2] += hi;
    aa[3] += lo;
}

void gf_weak_reduce (gf a) {
    uint64_t mask = (1ull<<28) - 1;
    uint64_t tmp = a->limb[15] >> 28;
    a->limb[8] += tmp;
    for (unsigned int i=15; i>0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i-1]>>28);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __P448_H__ */
