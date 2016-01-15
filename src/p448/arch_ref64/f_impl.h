/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P448_H__
#define __P448_H__ 1

#include "f_field.h"

#include <stdint.h>
#include <assert.h>
#include <string.h>

#define FIELD_LITERAL(a,b,c,d,e,f,g,h) {{a,b,c,d,e,f,g,h}}

#ifdef __cplusplus
extern "C" {
#endif

/* -------------- Inline functions begin here -------------- */

void gf_add_RAW (gf  out, const gf  a, const gf  b) {
    unsigned int i;
    for (i=0; i<8; i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
    gf_weak_reduce(out);
}

void gf_sub_RAW (gf  out, const gf  a, const gf  b) {
    unsigned int i;
    uint64_t co1 = ((1ull<<56)-1)*2, co2 = co1-2;
    for (i=0; i<8; i++) {
        out->limb[i] = a->limb[i] - b->limb[i] + ((i==4) ? co2 : co1);
    }
    gf_weak_reduce(out);
}

void gf_bias (gf  a, int amt) {
    (void) a;
    (void) amt;
}

void gf_weak_reduce (gf  a) {
    uint64_t mask = (1ull<<56) - 1;
    uint64_t tmp = a->limb[7] >> 56;
    int i;
    a->limb[4] += tmp;
    for (i=7; i>0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i-1]>>56);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __P448_H__ */
