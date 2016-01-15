/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P25519_H__
#define __P25519_H__ 1

#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "decaf/decaf_255.h"
#include "word.h"

#define LBITS 51
#define FIELD_LITERAL(a,b,c,d,e) {{ a,b,c,d,e }}

#ifdef __cplusplus
extern "C" {
#endif

/* -------------- Inline functions begin here -------------- */

void
gf_25519_add_RAW (
    gf_25519_t out,
    const gf_25519_t a,
    const gf_25519_t b
) {
    unsigned int i;
    for (i=0; i<5; i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
    gf_25519_weak_reduce(out);
}

void
gf_25519_sub_RAW (
    gf_25519_t out,
    const gf_25519_t a,
    const gf_25519_t b
) {
    unsigned int i;
    uint64_t co1 = ((1ull<<51)-1)*2, co2 = co1-36;
    for (i=0; i<5; i++) {
        out->limb[i] = a->limb[i] - b->limb[i] + ((i==0) ? co2 : co1);
    }
    gf_25519_weak_reduce(out);
}

void
gf_25519_copy (
    gf_25519_t out,
    const gf_25519_t a
) {
    memcpy(out,a,sizeof(*a));
}

void
gf_25519_bias (
    gf_25519_t a,
    int amt
) {
    (void) a;
    (void) amt;
}

void
gf_25519_weak_reduce (
    gf_25519_t a
) {
    uint64_t mask = (1ull<<51) - 1;
    uint64_t tmp = a->limb[4] >> 51;
    int i;
    for (i=4; i>0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i-1]>>51);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp*19;
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __P25519_H__ */
