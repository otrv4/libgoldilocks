/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P448_H__
#define __P448_H__ 1

#include "word.h"

#include <stdint.h>
#include <assert.h>

typedef struct gf_448_s {
  uint32_t limb[16];
} __attribute__((aligned(32))) gf_448_s, gf_448_t[1];

#define LBITS 28
#define LIMB(x) (x##ull)&((1ull<<LBITS)-1), (x##ull)>>LBITS
#define FIELD_LITERAL(a,b,c,d,e,f,g,h) \
    {{LIMB(a),LIMB(b),LIMB(c),LIMB(d),LIMB(e),LIMB(f),LIMB(g),LIMB(h)}}

#ifdef __cplusplus
extern "C" {
#endif

static __inline__ void
p448_add_RAW (
    gf_448_t out,
    const gf_448_t a,
    const gf_448_t b
) __attribute__((unused,always_inline));
             
static __inline__ void
p448_sub_RAW (
    gf_448_t out,
    const gf_448_t a,
    const gf_448_t b
) __attribute__((unused,always_inline));
             
static __inline__ void
p448_copy (
    gf_448_t out,
    const gf_448_t a
) __attribute__((unused,always_inline));
             
static __inline__ void
p448_weak_reduce (
    gf_448_t inout
) __attribute__((unused,always_inline));
             
void
p448_strong_reduce (
    gf_448_t inout
);
             
static __inline__ void
p448_bias (
    gf_448_t inout,
    int amount
) __attribute__((unused,always_inline));

void
p448_mul (
    gf_448_s *__restrict__ out,
    const gf_448_t a,
    const gf_448_t b
);

void
p448_mulw (
    gf_448_s *__restrict__ out,
    const gf_448_t a,
    uint64_t b
);

void
p448_sqr (
    gf_448_s *__restrict__ out,
    const gf_448_t a
);

void
p448_serialize (
    uint8_t *serial,
    const gf_448_t x
);

mask_t
p448_deserialize (
    gf_448_t x,
    const uint8_t serial[56]
);

/* -------------- Inline functions begin here -------------- */

void
p448_add_RAW (
    gf_448_t out,
    const gf_448_t a,
    const gf_448_t b
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint32xn_t); i++) {
        ((uint32xn_t*)out)[i] = ((const uint32xn_t*)a)[i] + ((const uint32xn_t*)b)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
    */
}

void
p448_sub_RAW (
    gf_448_t out,
    const gf_448_t a,
    const gf_448_t b
) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint32xn_t); i++) {
        ((uint32xn_t*)out)[i] = ((const uint32xn_t*)a)[i] - ((const uint32xn_t*)b)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] - b->limb[i];
    }
    */
}

void
p448_copy (
    gf_448_t out,
    const gf_448_t a
) {
  *out = *a;
}

void
p448_bias (
    gf_448_t a,
    int amt
) {
    uint32_t co1 = ((1ull<<28)-1)*amt, co2 = co1-amt;
    uint32x4_t lo = {co1,co1,co1,co1}, hi = {co2,co1,co1,co1};
    uint32x4_t *aa = (uint32x4_t*) a;
    aa[0] += lo;
    aa[1] += lo;
    aa[2] += hi;
    aa[3] += lo;
}

void
p448_weak_reduce (
    gf_448_t a
) {
    uint64_t mask = (1ull<<28) - 1;
    uint64_t tmp = a->limb[15] >> 28;
    int i;
    a->limb[8] += tmp;
    for (i=15; i>0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i-1]>>28);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __P448_H__ */
