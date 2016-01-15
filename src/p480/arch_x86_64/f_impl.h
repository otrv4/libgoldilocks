/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __gf_480_H__
#define __gf_480_H__ 1

#include <stdint.h>
#include <assert.h>

#include "word.h"

typedef struct gf_480_t {
  uint64_t limb[8];
} __attribute__((aligned(32))) gf_480_t;

#ifdef __cplusplus
extern "C" {
#endif
             
static __inline__ void
gf_480_weak_reduce (
    gf_480_t *inout
) __attribute__((unused,always_inline));
             
void
gf_480_strong_reduce (
    gf_480_t *inout
);
  
static __inline__ void
gf_480_bias (
    gf_480_t *inout,
    int amount
) __attribute__((unused,always_inline));
         
void
gf_480_mul (
    gf_480_t *__restrict__ out,
    const gf_480_t *a,
    const gf_480_t *b
);

void
gf_480_mulw (
    gf_480_t *__restrict__ out,
    const gf_480_t *a,
    uint64_t b
);

void
gf_480_sqr (
    gf_480_t *__restrict__ out,
    const gf_480_t *a
);

void
gf_480_serialize (
    uint8_t *serial,
    const struct gf_480_t *x
);

mask_t
gf_480_deserialize (
    gf_480_t *x,
    const uint8_t serial[60]
);

/* -------------- Inline functions begin here -------------- */

void
gf_480_add_RAW (
    gf_480_t *out,
    const gf_480_t *a,
    const gf_480_t *b
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = ((const uint64xn_t*)a)[i] + ((const uint64xn_t*)b)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
    */
}

void
gf_480_sub_RAW (
    gf_480_t *out,
    const gf_480_t *a,
    const gf_480_t *b
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = ((const uint64xn_t*)a)[i] - ((const uint64xn_t*)b)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] - b->limb[i];
    }
    */
}

void
gf_480_copy (
    gf_480_t *out,
    const gf_480_t *a
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(big_register_t); i++) {
        ((big_register_t *)out)[i] = ((const big_register_t *)a)[i];
    }
}

void
gf_480_bias (
    gf_480_t *a,
    int amt
) {
    uint64_t co1 = ((1ull<<60)-1)*amt, co2 = co1-amt;
    
#if __AVX2__
    uint64x4_t lo = {co1,co1,co1,co1}, hi = {co2,co1,co1,co1};
    uint64x4_t *aa = (uint64x4_t*) a;
    aa[0] += lo;
    aa[1] += hi;
#elif __SSE2__
    uint64x2_t lo = {co1,co1}, hi = {co2,co1};
    uint64x2_t *aa = (uint64x2_t*) a;
    aa[0] += lo;
    aa[1] += lo;
    aa[2] += hi;
    aa[3] += lo;
#else
    unsigned int i;
    for (i=0; i<sizeof(*a)/sizeof(uint64_t); i++) {
        a->limb[i] += (i==4) ? co2 : co1;
    }
#endif
}

void
gf_480_weak_reduce (
    gf_480_t *a
) {
    /* PERF: use pshufb/palignr if anyone cares about speed of this */
    uint64_t mask = (1ull<<60) - 1;
    uint64_t tmp = a->limb[7] >> 60;
    int i;
    a->limb[4] += tmp;
    for (i=7; i>0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i-1]>>60);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __gf_480_H__ */
