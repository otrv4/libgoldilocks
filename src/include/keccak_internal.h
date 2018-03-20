/**
 * @cond internal
 * @file keccak_internal.h
 * @copyright
 *   Copyright (c) 2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Keccak internal interfaces.  Will be used by STROBE once reintegrated.
 */
#ifndef __GOLDILOCKS_KECCAK_INTERNAL_H__
#define __GOLDILOCKS_KECCAK_INTERNAL_H__ 1

#include <stdint.h>

/* The internal, non-opaque definition of the goldilocks_sponge struct. */
typedef union {
    uint64_t w[25]; uint8_t b[25*8];
} kdomain_t[1];

typedef struct goldilocks_kparams_s {
    uint8_t position, flags, rate, start_round, pad, rate_pad, max_out, remaining;
} goldilocks_kparams_s, goldilocks_kparams_t[1];

typedef struct goldilocks_keccak_sponge_s {
    kdomain_t state;
    goldilocks_kparams_t params;
} goldilocks_keccak_sponge_s, goldilocks_keccak_sponge_t[1];

#define INTERNAL_SPONGE_STRUCT 1

void __attribute__((noinline)) keccakf(kdomain_t state, uint8_t start_round);

static inline void dokeccak (goldilocks_keccak_sponge_t goldilocks_sponge) {
    keccakf(goldilocks_sponge->state, goldilocks_sponge->params->start_round);
    goldilocks_sponge->params->position = 0;
}

#endif /* __GOLDILOCKS_KECCAK_INTERNAL_H__ */
