/**
 * @file decaf/shake.h
 * @copyright
 *   Based on CC0 code by David Leon Gil, 2015 \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief SHA-3-n and SHAKE-n instances.
 * @warning EXPERIMENTAL!  The names, parameter orders etc are likely to change.
 */

#ifndef __SHAKE_H__
#define __SHAKE_H__

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h> /* for NULL */

#include <decaf/common.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef INTERNAL_SPONGE_STRUCT
    /** Sponge container object for the various primitives. */
    typedef struct keccak_sponge_s {
        /** @cond internal */
        uint64_t opaque[26];
        /** @endcond */
    } keccak_sponge_s;

    /** Convenience GMP-style one-element array version */
    typedef struct keccak_sponge_s keccak_sponge_t[1];

    /** Parameters for sponge construction, distinguishing SHA3 and
     * SHAKE instances.
     */
    struct kparams_s;
#endif

/**
 * @brief Initialize a sponge context object.
 * @param [out] sponge The object to initialize.
 * @param [in] params The sponge's parameter description.
 */
void sponge_init (
    keccak_sponge_t sponge,
    const struct kparams_s *params
) API_VIS;

/**
 * @brief Absorb data into a SHA3 or SHAKE hash context.
 * @param [inout] sponge The context.
 * @param [in] in The input data.
 * @param [in] len The input data's length in bytes.
 */
void sha3_update (
    struct keccak_sponge_s * __restrict__ sponge,
    const uint8_t *in,
    size_t len
) API_VIS;

/**
 * @brief Squeeze output data from a SHA3 or SHAKE hash context.
 * This does not destroy or re-initialize the hash context, and
 * sha3 output can be called more times.
 *
 * @param [inout] sponge The context.
 * @param [out] out The output data.
 * @param [in] len The requested output data length in bytes.
 */  
void sha3_output (
    keccak_sponge_t sponge,
    uint8_t * __restrict__ out,
    size_t len
) API_VIS;

/**
 * @brief Return the default output length of the sponge construction,
 * for the purpose of C++ default operators.
 *
 * Returns n/8 for SHA3-n and 2n/8 for SHAKE-n.
 */  
size_t sponge_default_output_bytes (
    const keccak_sponge_t sponge /**< [inout] The context. */
) API_VIS;

/**
 * @brief Destroy a SHA3 or SHAKE sponge context by overwriting it with 0.
 * @param [out] sponge The context.
 */  
void sponge_destroy (
    keccak_sponge_t sponge
) API_VIS;

/**
 * @brief Hash (in) to (out)
 * @param [in] in The input data.
 * @param [in] inlen The length of the input data.
 * @param [out] out A buffer for the output data.
 * @param [in] outlen The length of the output data.
 * @param [in] params The parameters of the sponge hash.
 */  
void sponge_hash (
    const uint8_t *in,
    size_t inlen,
    uint8_t *out,
    size_t outlen,
    const struct kparams_s *params
) API_VIS;

/* FUTURE: expand/doxygenate individual SHAKE/SHA3 instances? */

/** @cond internal */
#define DECSHAKE(n) \
    extern const struct kparams_s SHAKE##n##_params_s API_VIS; \
    typedef struct shake##n##_ctx_s { keccak_sponge_t s; } shake##n##_ctx_t[1]; \
    static inline void NONNULL shake##n##_init(shake##n##_ctx_t sponge) { \
        sponge_init(sponge->s, &SHAKE##n##_params_s); \
    } \
    static inline void NONNULL shake##n##_gen_init(keccak_sponge_t sponge) { \
        sponge_init(sponge, &SHAKE##n##_params_s); \
    } \
    static inline void NONNULL shake##n##_update(shake##n##_ctx_t sponge, const uint8_t *in, size_t inlen ) { \
        sha3_update(sponge->s, in, inlen); \
    } \
    static inline void  NONNULL shake##n##_final(shake##n##_ctx_t sponge, uint8_t *out, size_t outlen ) { \
        sha3_output(sponge->s, out, outlen); \
        sponge_init(sponge->s, &SHAKE##n##_params_s); \
    } \
    static inline void  NONNULL shake##n##_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) { \
        sponge_hash(in,inlen,out,outlen,&SHAKE##n##_params_s); \
    } \
    static inline void  NONNULL shake##n##_destroy( shake##n##_ctx_t sponge ) { \
        sponge_destroy(sponge->s); \
    }

#define DECSHA3(n) \
    extern const struct kparams_s SHA3_##n##_params_s API_VIS; \
    typedef struct sha3_##n##_ctx_s { keccak_sponge_t s; } sha3_##n##_ctx_t[1]; \
    static inline void NONNULL sha3_##n##_init(sha3_##n##_ctx_t sponge) { \
        sponge_init(sponge->s, &SHA3_##n##_params_s); \
    } \
    static inline void NONNULL sha3_##n##_gen_init(keccak_sponge_t sponge) { \
        sponge_init(sponge, &SHA3_##n##_params_s); \
    } \
    static inline void NONNULL sha3_##n##_update(sha3_##n##_ctx_t sponge, const uint8_t *in, size_t inlen ) { \
        sha3_update(sponge->s, in, inlen); \
    } \
    static inline void NONNULL sha3_##n##_final(sha3_##n##_ctx_t sponge, uint8_t *out, size_t outlen ) { \
        sha3_output(sponge->s, out, outlen); \
        sponge_init(sponge->s, &SHA3_##n##_params_s); \
    } \
    static inline void NONNULL sha3_##n##_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) { \
        sponge_hash(in,inlen,out,outlen,&SHA3_##n##_params_s); \
    } \
    static inline void NONNULL sha3_##n##_destroy(sha3_##n##_ctx_t sponge) { \
        sponge_destroy(sponge->s); \
    }
/** @endcond */

DECSHAKE(128)
DECSHAKE(256)
DECSHA3(224)
DECSHA3(256)
DECSHA3(384)
DECSHA3(512)

#ifdef __cplusplus
} /* extern "C" */
#endif
    
#endif /* __SHAKE_H__ */
