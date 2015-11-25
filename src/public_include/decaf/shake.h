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

/** @cond internal */
#define API_VIS __attribute__((visibility("default")))
#define WARN_UNUSED __attribute__((warn_unused_result))
#define NONNULL1 __attribute__((nonnull(1)))
#define NONNULL2 __attribute__((nonnull(1,2)))
#define NONNULL13 __attribute__((nonnull(1,3)))
#define NONNULL3 __attribute__((nonnull(1,2,3)))
#define INLINE __inline__ __attribute__((always_inline))
#define UNUSED __attribute__((unused))
/** @endcond */

#ifndef INTERNAL_SPONGE_STRUCT
    /** Sponge container object for the various primitives. */
    typedef struct keccak_sponge_s {
        /** @cond internal */
        uint64_t opaque[26];
        /** @endcond */
    } keccak_sponge_t[1];
    struct kparams_s;
#endif
typedef struct keccak_sponge_s keccak_strobe_t[1], keccak_prng_t[1];

#ifdef __cplusplus
extern "C" {
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
 *
 * @param [inout] sponge The context.
 */  
size_t sponge_default_output_bytes (
    const keccak_sponge_t sponge
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
    static inline void NONNULL1 shake##n##_init(shake##n##_ctx_t sponge) { \
        sponge_init(sponge->s, &SHAKE##n##_params_s); \
    } \
    static inline void NONNULL1 shake##n##_gen_init(keccak_sponge_t sponge) { \
        sponge_init(sponge, &SHAKE##n##_params_s); \
    } \
    static inline void NONNULL2 shake##n##_update(shake##n##_ctx_t sponge, const uint8_t *in, size_t inlen ) { \
        sha3_update(sponge->s, in, inlen); \
    } \
    static inline void  NONNULL2 shake##n##_final(shake##n##_ctx_t sponge, uint8_t *out, size_t outlen ) { \
        sha3_output(sponge->s, out, outlen); \
        sponge_init(sponge->s, &SHAKE##n##_params_s); \
    } \
    static inline void  NONNULL13 shake##n##_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) { \
        sponge_hash(in,inlen,out,outlen,&SHAKE##n##_params_s); \
    } \
    static inline void  NONNULL1 shake##n##_destroy( shake##n##_ctx_t sponge ) { \
        sponge_destroy(sponge->s); \
    }
    
#define DECSHA3(n) \
    extern const struct kparams_s SHA3_##n##_params_s API_VIS; \
    typedef struct sha3_##n##_ctx_s { keccak_sponge_t s; } sha3_##n##_ctx_t[1]; \
    static inline void NONNULL1 sha3_##n##_init(sha3_##n##_ctx_t sponge) { \
        sponge_init(sponge->s, &SHA3_##n##_params_s); \
    } \
    static inline void NONNULL1 sha3_##n##_gen_init(keccak_sponge_t sponge) { \
        sponge_init(sponge, &SHA3_##n##_params_s); \
    } \
    static inline void NONNULL2 sha3_##n##_update(sha3_##n##_ctx_t sponge, const uint8_t *in, size_t inlen ) { \
        sha3_update(sponge->s, in, inlen); \
    } \
    static inline void NONNULL2 sha3_##n##_final(sha3_##n##_ctx_t sponge, uint8_t *out, size_t outlen ) { \
        sha3_output(sponge->s, out, outlen); \
        sponge_init(sponge->s, &SHA3_##n##_params_s); \
    } \
    static inline void NONNULL13 sha3_##n##_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) { \
        sponge_hash(in,inlen,out,outlen,&SHA3_##n##_params_s); \
    } \
    static inline void NONNULL1 sha3_##n##_destroy(sha3_##n##_ctx_t sponge) { \
        sponge_destroy(sponge->s); \
    }
/** @endcond */

DECSHAKE(128)
DECSHAKE(256)
DECSHA3(224)
DECSHA3(256)
DECSHA3(384)
DECSHA3(512)

/**
 * @brief Initialize a sponge-based CSPRNG from a buffer.
 *
 * @param [out] prng The prng object.
 * @param [in] in The initial data.
 * @param [in] len The length of the initial data.
 * @param [in] deterministic If zero, allow RNG to stir in nondeterministic
 * data from RDRAND or RDTSC.
 */
void spongerng_init_from_buffer (
    keccak_prng_t prng,
    const uint8_t * __restrict__ in,
    size_t len,
    int deterministic
) NONNULL2 API_VIS;

/* FIXME!! This interface has the opposite retval convention from other functions
 * in the library.  (0=success).  Should they be harmonized?
 */

/**
 * @brief Initialize a sponge-based CSPRNG from a file.
 *
 * @param [out] prng The prng object.
 * @param [in] file A name of a file containing initial data.
 * @param [in] len The length of the initial data.  Must be positive.
 * @param [in] deterministic If zero, allow RNG to stir in nondeterministic
 * data from RDRAND or RDTSC.
 *
 * @retval 0 Success.
 * @retval positive An error has occurred, and this was the errno.
 * @retval -1 An unknown error has occurred.
 * @retval -2 len was 0.
 */
int spongerng_init_from_file (
    keccak_prng_t prng,
    const char *file,
    size_t len,
    int deterministic
) NONNULL2 API_VIS WARN_UNUSED;


/* FIXME!! This interface has the opposite retval convention from other functions
 * in the library.  (0=success).  Should they be harmonized?
 */

/**
 * @brief Initialize a nondeterministic sponge-based CSPRNG from /dev/urandom.
 *
 * @param [out] sponge The sponge object.
 *
 * @retval 0 Success.
 * @retval positive An error has occurred, and this was the errno.
 * @retval -1 An unknown error has occurred.
 */
int spongerng_init_from_dev_urandom (
    keccak_prng_t prng
) API_VIS WARN_UNUSED;

/**
 * @brief Output bytes from a sponge-based CSPRNG.
 *
 * @param [inout] sponge The sponge object.
 * @param [out] out The output buffer.
 * @param [in] len The output buffer's length.
 */
void spongerng_next (
    keccak_prng_t prng,
    uint8_t * __restrict__ out,
    size_t len
) API_VIS;

/**
 * @brief Stir entropy data into a sponge-based CSPRNG from a buffer.
 *
 * @param [out] sponge The sponge object.
 * @param [in] in The entropy data.
 * @param [in] len The length of the initial data.
 */
void spongerng_stir (
    keccak_prng_t prng,
    const uint8_t * __restrict__ in,
    size_t len
) NONNULL2 API_VIS;

extern const struct kparams_s STROBE_128 API_VIS;
extern const struct kparams_s STROBE_256 API_VIS;
extern const struct kparams_s STROBE_KEYED_128 API_VIS;
extern const struct kparams_s STROBE_KEYED_256 API_VIS;

typedef enum {
    STROBE_MODE_ABSORB    = 0,
    STROBE_MODE_DUPLEX    = 1,
    STROBE_MODE_ABSORB_R  = 2,
    STROBE_MODE_DUPLEX_R  = 3,
    /* FIXME: no bits allocated in .py version */
    STROBE_MODE_PLAINTEXT = 4,
    STROBE_MODE_SQUEEZE   = 5, 
    STROBE_MODE_FORGET    = 6,
    STROBE_MODE_SQUEEZE_R = 7
} strobe_mode_t;

static const uint32_t
    STROBE_FLAG_CLIENT_SENT = 1<<8,
    STROBE_FLAG_IMPLICIT    = 1<<9,
    STROBE_FLAG_FORGET      = 1<<12,
    STROBE_FLAG_NO_LENGTH   = 1<<15,
    
    /* After 1<<16, flags don't go to the sponge anymore, they just affect the handling */
    STROBE_FLAG_RECV        = 1<<16,
    STROBE_FLAG_RUN_F       = 1<<17,
    STROBE_FLAG_MORE        = 1<<18,
    STROBE_FLAG_LENGTH_64   = 1<<19,
    STROBE_FLAG_NONDIR      = STROBE_FLAG_IMPLICIT; /* Currently same as implicit */

/** Automatic flags implied by the mode */
/* HACK: SQUEEZE_R is treated as directional because its' MAC */
#define STROBE_AUTO_FLAGS(_mode)                           \
    (     (((_mode)&1) ? STROBE_FLAG_RUN_F : 0)            \
        | (( ((_mode) & ~2) == STROBE_MODE_ABSORB          \
          ||  (_mode)       == STROBE_MODE_SQUEEZE         \
          ||  (_mode)       == STROBE_MODE_FORGET          \
          ) ? STROBE_FLAG_IMPLICIT|STROBE_FLAG_NONDIR : 0) \
    )

#define STROBE_CONTROL_WORD(_name,_id,_mode,_flags) \
    static const uint32_t _name = _id | (_mode<<10) | (_mode<<29) | _flags | STROBE_AUTO_FLAGS(_mode)

STROBE_CONTROL_WORD(STROBE_CW_INIT,              0x00, STROBE_MODE_ABSORB,    0);
                                                 
/* Ciphers */                                    
STROBE_CONTROL_WORD(STROBE_CW_FIXED_KEY,          0x10, STROBE_MODE_ABSORB,    0);
STROBE_CONTROL_WORD(STROBE_CW_STATIC_PUB,         0x11, STROBE_MODE_PLAINTEXT, 0);
STROBE_CONTROL_WORD(STROBE_CW_DH_EPH,             0x12, STROBE_MODE_PLAINTEXT, 0);
STROBE_CONTROL_WORD(STROBE_CW_DH_KEY,             0x13, STROBE_MODE_ABSORB,    0);
STROBE_CONTROL_WORD(STROBE_CW_PRNG,               0x18, STROBE_MODE_SQUEEZE,   STROBE_FLAG_FORGET);
STROBE_CONTROL_WORD(STROBE_CW_SESSION_HASH,       0x19, STROBE_MODE_SQUEEZE,   0);

/* Reuse for PRNG */
STROBE_CONTROL_WORD(STROBE_CW_PRNG_INITIAL_SEED,  0x10, STROBE_MODE_ABSORB,    STROBE_FLAG_LENGTH_64);
STROBE_CONTROL_WORD(STROBE_CW_PRNG_RESEED,        0x11, STROBE_MODE_ABSORB,    STROBE_FLAG_LENGTH_64);
STROBE_CONTROL_WORD(STROBE_CW_PRNG_CPU_SEED,      0x12, STROBE_MODE_ABSORB,    0);
STROBE_CONTROL_WORD(STROBE_CW_PRNG_USER_SEED,     0x13, STROBE_MODE_ABSORB,    STROBE_FLAG_LENGTH_64);
STROBE_CONTROL_WORD(STROBE_CW_PRNG_PRNG,          0x14, STROBE_MODE_SQUEEZE,   STROBE_FLAG_LENGTH_64 | STROBE_FLAG_FORGET);

/* Signatures */                                 
STROBE_CONTROL_WORD(STROBE_CW_SIG_SCHEME,         0x20, STROBE_MODE_ABSORB,    0);
STROBE_CONTROL_WORD(STROBE_CW_SIG_PK,             0x21, STROBE_MODE_ABSORB,    0);
STROBE_CONTROL_WORD(STROBE_CW_SIG_EPH,            0x22, STROBE_MODE_PLAINTEXT, 0);
STROBE_CONTROL_WORD(STROBE_CW_SIG_CHAL,           0x23, STROBE_MODE_SQUEEZE,   0);
STROBE_CONTROL_WORD(STROBE_CW_SIG_RESP,           0x24, STROBE_MODE_DUPLEX,    0);


/* Payloads and encrypted data */

STROBE_CONTROL_WORD(STROBE_CW_PAYLOAD_PLAINTEXT,  0x30, STROBE_MODE_PLAINTEXT, 0);
STROBE_CONTROL_WORD(STROBE_CW_PAYLOAD_CIPHERTEXT, 0x31, STROBE_MODE_DUPLEX,    0);
STROBE_CONTROL_WORD(STROBE_CW_MAC,                0x32, STROBE_MODE_SQUEEZE_R, STROBE_FLAG_FORGET);
STROBE_CONTROL_WORD(STROBE_CW_AD_EXPLICIT,        0x34, STROBE_MODE_PLAINTEXT, 0);
STROBE_CONTROL_WORD(STROBE_CW_AD_IMPLICIT,        0x35, STROBE_MODE_ABSORB,    0);
STROBE_CONTROL_WORD(STROBE_CW_NONCE_EXPLICIT,     0x36, STROBE_MODE_PLAINTEXT, 0);
STROBE_CONTROL_WORD(STROBE_CW_NONCE_IMPLICIT,     0x37, STROBE_MODE_ABSORB,    0);

STROBE_CONTROL_WORD(STROBE_CW_STREAMING_PLAINTEXT,0x30, STROBE_MODE_PLAINTEXT, STROBE_FLAG_NO_LENGTH); /* TODO: orly? */

/* Change spec, control flow, etc */
STROBE_CONTROL_WORD(STROBE_CW_COMPRESS,           0x40, STROBE_MODE_ABSORB_R,  0);
/* FIXME: adjust this respec logic */
STROBE_CONTROL_WORD(STROBE_CW_RESPEC_INFO,        0x41, STROBE_MODE_ABSORB,    STROBE_FLAG_RUN_F | STROBE_FLAG_FORGET);
STROBE_CONTROL_WORD(STROBE_CW_RESPEC,             0x42, STROBE_MODE_ABSORB_R,  STROBE_FLAG_RUN_F);
STROBE_CONTROL_WORD(STROBE_CW_FORK,               0x43, STROBE_MODE_ABSORB_R,  STROBE_FLAG_RUN_F | STROBE_FLAG_FORGET);
/* FIXME: instance can be rolled back to recover other INSTANCEs */
STROBE_CONTROL_WORD(STROBE_CW_INSTANCE,           0x44, STROBE_MODE_ABSORB_R,  STROBE_FLAG_FORGET);
STROBE_CONTROL_WORD(STROBE_CW_ACKNOWLEDGE,        0x45, STROBE_MODE_PLAINTEXT, 0);

static INLINE UNUSED WARN_UNUSED uint32_t
strobe_cw_recv(uint32_t cw) {
    uint32_t recv_toggle = (cw & STROBE_FLAG_NONDIR) ? 0 : STROBE_FLAG_RECV;
    if (cw & STROBE_FLAG_IMPLICIT) {
        return cw ^ recv_toggle;
    } else {   
        uint32_t modes_2[8] = {
            /* Note: most of these really shouldn't happen... */
            STROBE_MODE_ABSORB,
            STROBE_MODE_DUPLEX_R,
            STROBE_MODE_ABSORB_R,
            STROBE_MODE_DUPLEX,
            STROBE_MODE_PLAINTEXT,
            STROBE_MODE_SQUEEZE,
            STROBE_MODE_FORGET,
            STROBE_MODE_ABSORB
        };
    
        return ((cw & ((1<<29)-1)) | (modes_2[cw>>29]<<29)) ^ recv_toggle;
    }
}

#define STROBE_MAX_AUTH_BYTES 32


/**
 * @brief Initialize Strobe protocol context.
 * @param [out] strobe The uninitialized strobe object.
 * @param [in] Strobe parameter descriptor
 * @param [in] am_client Nonzero if this party
 * is the client.
 */
void strobe_init (
    keccak_strobe_t strobe,
    const struct kparams_s *params,
    const char *proto,
    uint8_t am_client
) NONNULL2 API_VIS;

/**
 * @brief Run a transaction against a STROBE state.
 * @param [inout] strobe The initialized STROBE object.
 * @param [out] out The output.
 * @param [in] in The input.
 * @param [in] len The length of the input/output.
 * @param [in] cw_flags The control word with flags.
 */
void strobe_transact (
    keccak_strobe_t strobe,
    unsigned char *out,
    const unsigned char *in,
    size_t len,
    uint32_t cw_flags
) NONNULL1 API_VIS;

/**
 * @brief Send plaintext in strobe context.
 * @param [inout] The initialized strobe object.
 * @param [in] in The plaintext.
 * @param [in] len The length of the plaintext.
 * @param [in] iSent Nonzero if this side of exchange sent the plaintext.
 */
static INLINE UNUSED void strobe_plaintext (
    keccak_strobe_t strobe,
    const unsigned char *in,
    uint16_t len,
    uint8_t iSent
) {
    strobe_transact(
        strobe, NULL, in, len,
        iSent ? STROBE_CW_PAYLOAD_PLAINTEXT
              : strobe_cw_recv(STROBE_CW_PAYLOAD_PLAINTEXT)
    );
}
   
/**
 * @brief Report authenticated data in strobe context.
 * @param [inout] The initialized strobe object.
 * @param [in] in The plaintext.
 * @param [in] len The length of the ad.
 */
static INLINE UNUSED void strobe_ad (
    keccak_strobe_t strobe,
    const unsigned char *in,
    size_t len
) {
    strobe_transact( strobe, NULL, in, len, STROBE_CW_AD_EXPLICIT );
}
  
/**
 * @brief Set nonce in strobe context.
 * @param [inout] The initialized strobe object.
 * @param [in] in The nonce.
 * @param [in] len The length of the nonce.
 */
static INLINE UNUSED void strobe_nonce (
    keccak_strobe_t strobe,
    const unsigned char *in,
    uint16_t len
) {
    strobe_transact( strobe, NULL, in, len, STROBE_CW_NONCE_EXPLICIT );
}
   
/**
 * @brief Set key in strobe context.
 * @param [inout] The initialized strobe object.
 * @param [in] in The key.
 * @param [in] len The length of the key.
 */
static INLINE UNUSED void
strobe_key (
    keccak_strobe_t strobe,
    const unsigned char *in,
    uint16_t len
) {
    strobe_transact( strobe, NULL, in, len, STROBE_CW_DH_KEY ); /* FIXME: what about other kinds of keys? */
}

    
/**
 * @brief Produce an authenticator.
 * @param [inout] strobe The Strobe protocol context.
 * @param [out] out The authenticator
 * @param len The length.
 */
static INLINE UNUSED void
strobe_produce_auth (
    keccak_strobe_t strobe,
    unsigned char *out,
    uint16_t len
) {
    strobe_transact( strobe, out, NULL, len, STROBE_CW_MAC );
}
   
/**
 * @brief Encrypt bytes from in to out.
 * @warning Doesn't produce an auth tag.
 * @param [inout] strobe The Strobe protocol context.
 * @param [in] in The plaintext.
 * @param [out] out The ciphertext.
 * @param [in] len The length of plaintext and ciphertext.
 */
static INLINE UNUSED void
strobe_encrypt (
   keccak_strobe_t strobe,
   unsigned char *out,
   const unsigned char *in,
   uint16_t len
) {
   strobe_transact(strobe, out, in, len, STROBE_CW_PAYLOAD_CIPHERTEXT);
}
   
/**
 * @brief Decrypt bytes from in to out.
 * @warning Doesn't check an auth tag.
 * @param [inout] strobe The Strobe protocol context.
 * @param [in] in The ciphertext.
 * @param [out] out The plaintext.
 * @param [in] len The length of plaintext and ciphertext.
 */
static INLINE UNUSED void
strobe_decrypt (
   keccak_strobe_t strobe,
   unsigned char *out,
   const unsigned char *in,
   uint16_t len
) {
   strobe_transact(strobe, out, in, len, strobe_cw_recv(STROBE_CW_PAYLOAD_CIPHERTEXT));
}

/**
 * @brief Produce a session-bound pseudorandom value.
 *
 * @warning This "prng" value is NOT suitable for
 * refreshing forward secrecy!  It's to replace things
 * like TCP session hash.
 *
 * @param [inout] strobe The Strobe protocol context
 * @param [out] out The output random data.
 * @param len The length.
 */
static inline void strobe_prng (
    keccak_strobe_t strobe,
    unsigned char *out,
    uint16_t len
) {
    strobe_transact( strobe, out, NULL, len, STROBE_CW_PRNG );
}

/**
 * @brief Verify an authenticator.
 * @param [inout] strobe The Strobe protocol context
 * @param [in] in The authenticator
 * @param len The length, which must be no more than
 * @todo 32?
 * @retval DECAF_SUCCESS The operation applied successfully.
 * @retval DECAF_FAILURE The operation failed because of a
 * bad validator (or because you aren't keyed)
 */
decaf_error_t strobe_verify_auth (
    keccak_strobe_t strobe,
    const unsigned char *in,
    uint16_t len
) WARN_UNUSED NONNULL2 API_VIS;

/**
 * @brief Respecify Strobe protocol object's crypto.
 * @param [inout] The initialized strobe context.
 * @param [in] Strobe parameter descriptor
 * @param [in] am_client Nonzero if this party
 * is the client.
 */
void strobe_respec (
    keccak_strobe_t strobe,
    const struct kparams_s *params
) NONNULL2 API_VIS;
    
#define strobe_destroy sponge_destroy

#ifdef __cplusplus
} /* extern "C" */
#endif

#undef API_VIS
#undef WARN_UNUSED
#undef NONNULL1
#undef NONNULL13
#undef NONNULL2
#undef NONNULL3
#undef INLINE
#undef UNUSED
    
#endif /* __SHAKE_H__ */
