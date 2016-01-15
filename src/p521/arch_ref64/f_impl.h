/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P521_H__
#define __P521_H__ 1

#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "word.h"

typedef struct gf_521_t {
  uint64_t limb[9];
} gf_521_t;

#ifdef __cplusplus
extern "C" {
#endif
             
static __inline__ void
gf_521_weak_reduce (
    gf_521_t *inout
) __attribute__((unused));
             
void
gf_521_strong_reduce (
    gf_521_t *inout
);

static __inline__ void
gf_521_bias (
    gf_521_t *inout,
    int amount
) __attribute__((unused));
         
void
gf_521_mul (
    gf_521_t *__restrict__ out,
    const gf_521_t *a,
    const gf_521_t *b
);

void
gf_521_mulw (
    gf_521_t *__restrict__ out,
    const gf_521_t *a,
    uint64_t b
);

void
gf_521_sqr (
    gf_521_t *__restrict__ out,
    const gf_521_t *a
);

void
gf_521_serialize (
    uint8_t *serial,
    const struct gf_521_t *x
);

mask_t
gf_521_deserialize (
    gf_521_t *x,
    const uint8_t serial[66]
);

/* -------------- Inline functions begin here -------------- */

void
gf_521_add_RAW (
    gf_521_t *out,
    const gf_521_t *a,
    const gf_521_t *b
) {
    unsigned int i;
    for (i=0; i<9; i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
    gf_521_weak_reduce(out);
}

void
gf_521_sub_RAW (
    gf_521_t *out,
    const gf_521_t *a,
    const gf_521_t *b
) {
    unsigned int i;
    uint64_t co1 = ((1ull<<58)-1)*4, co2 = ((1ull<<57)-1)*4;
    for (i=0; i<9; i++) {
        out->limb[i] = a->limb[i] - b->limb[i] + ((i==8) ? co2 : co1);
    }
    gf_521_weak_reduce(out);
}

void
gf_521_copy (
    gf_521_t *out,
    const gf_521_t *a
) {
    memcpy(out,a,sizeof(*a));
}

void
gf_521_bias (
    gf_521_t *a,
    int amt
) {
    (void) a;
    (void) amt;
}

void
gf_521_weak_reduce (
    gf_521_t *a
) {
    uint64_t mask = (1ull<<58) - 1;
    uint64_t tmp = a->limb[8] >> 57;
    int i;
    for (i=8; i>0; i--) {
        a->limb[i] = (a->limb[i] & ((i==8) ? mask>>1 : mask)) + (a->limb[i-1]>>58);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __P521_H__ */
