/**
 * @cond internal
 * @file f_arithmetic.c
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Field-specific arithmetic.
 */

#include "field.h"
#include "constant_time.h"

const gf SQRT_MINUS_ONE = {FIELD_LITERAL(
    0x61b274a0ea0b0,
    0x0d5a5fc8f189d,
    0x7ef5e9cbd0c60,
    0x78595a6804c9e,
    0x2b8324804fc1d
)};

const gf MODULUS = {FIELD_LITERAL(
    0x7ffffffffffed, 0x7ffffffffffff, 0x7ffffffffffff, 0x7ffffffffffff, 0x7ffffffffffff
)};

/* Guarantee: a^2 x = 0 if x = 0; else a^2 x = 1 or SQRT_MINUS_ONE; */
void gf_isr (gf a, const gf x) {
    gf st[3], tmp1, tmp2;
    const struct { unsigned char sh, idx; } ops[] = {
        {1,2},{1,2},{3,1},{6,0},{1,2},{12,1},{25,1},{25,1},{50,0},{125,0},{2,2},{1,2}
    };
    st[0][0] = st[1][0] = st[2][0] = x[0];
    unsigned int i;
    for (i=0; i<sizeof(ops)/sizeof(ops[0]); i++) {
        gf_sqrn(tmp1, st[1^(i&1)], ops[i].sh);
        gf_mul(tmp2, tmp1, st[ops[i].idx]);
        st[i&1][0] = tmp2[0];
    }
    
    mask_t mask = gf_eq(st[1],ONE) | gf_eq(st[1],SQRT_MINUS_ONE);
    
    constant_time_select(tmp1, ONE, SQRT_MINUS_ONE, sizeof(tmp1), mask, 0);
    gf_mul(a,tmp1,st[0]);
}
