/**
 * @file decaf/strobe.h
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief STROBE experimental protocol framework.
 * @warning EXPERIMENTAL!  The names, parameter orders etc are likely to change.
 */

#ifndef __DECAF_STROBE_H__
#define __DECAF_STROBE_H__

#include <decaf/shake.h>

#ifdef __cplusplus
extern "C" {
#endif
    
/** Keccak STROBE structure as struct. */
typedef struct {
    decaf_keccak_sponge_t sponge; /**< Internal sponge object. */
} keccak_strobe_s;
    
/** Keccak STROBE structure as one-element array */
typedef keccak_strobe_s keccak_strobe_t[1];

/** STROBE parameters, 128-bit estimated security for hashing and encryption */
extern const struct decaf_kparams_s STROBE_128 API_VIS;

/** STROBE parameters, 256-bit estimated security for hashing and encryption */
extern const struct decaf_kparams_s STROBE_256 API_VIS;

/** STROBE parameters, 128-bit estimated security for encryption only (not hashing) */
extern const struct decaf_kparams_s STROBE_KEYED_128 API_VIS;

/** STROBE parameters, 256-bit estimated security for encryption only (not hashing) */
extern const struct decaf_kparams_s STROBE_KEYED_256 API_VIS;


/** Initialize Strobe protocol context. */
void strobe_init (
    keccak_strobe_t strobe,         /**< [out] The uninitialized strobe object. */
    const struct decaf_kparams_s *params, /**< [in] Parameter set descriptor. */
    const char *proto,              /**< [in] Unique identifier for the protocol.  TODO: define namespaces for this */
    uint8_t am_client               /**< [in] Nonzero if this party. */
) NONNULL API_VIS;

/** Run a transaction against a STROBE state. */
void strobe_transact (
    keccak_strobe_t strobe,  /**< [inout] The initialized STROBE object. */
    unsigned char *out,      /**< [out] The output. */
    const unsigned char *in, /**< [in] The input. */
    size_t len,              /**< [in] The length of the input/output. */
    uint32_t cw_flags        /**< [in] The control word with flags. */
) __attribute__((nonnull(1))) API_VIS;

/** Record a message sent in plaintext */
static INLINE UNUSED NONNULL void strobe_plaintext (
    keccak_strobe_t strobe,  /**< [inout] The STROBE object */
    const unsigned char *in, /**< [in] The message. */
    uint16_t len,            /**< [in] The length of the message. */
    uint8_t iSent            /**< [in] If nonzero, I sent the message. */
);

/** Report authenticated data in strobe context. */
static INLINE UNUSED NONNULL void
strobe_ad (
    keccak_strobe_t strobe,  /**< [inout] The strobe object. */
    const unsigned char *in, /**< [in] The plaintext. */
    size_t len               /**< [in] The length of the ad. */
);

/** Set nonce in strobe context. */
static INLINE UNUSED NONNULL void
strobe_nonce (
   keccak_strobe_t strobe,  /**< [inout] The initialized strobe object. */
   const unsigned char *in, /**< [in] The nonce. */
   uint16_t len             /**< [in] The length of the nonce. */
);

/** Set fixed key in strobe context. */
static INLINE UNUSED NONNULL void
strobe_fixed_key (
   keccak_strobe_t strobe,  /**< [inout] The initialized strobe object. */
   const unsigned char *in, /**< [in] The key. */
   uint16_t len             /**< [in] The length of the key. */
);

/** Set Diffie-Hellman key in strobe context. */
static INLINE UNUSED NONNULL void
strobe_dh_key (
   keccak_strobe_t strobe,  /**< [inout] The initialized strobe object. */
   const unsigned char *in, /**< [in] The key. */
   uint16_t len             /**< [in] The length of the key. */
);

/** The maximum number of bytes that strobe_produce_auth can spit out. */
#define STROBE_MAX_AUTH_BYTES 32
 
/** Produce an authenticator. */
static INLINE UNUSED NONNULL void
strobe_produce_auth (
   keccak_strobe_t strobe, /**< [inout] The Strobe protocol context. */
   unsigned char *out,     /**< [out] The authenticator. */
   uint16_t len            /**< [in] The length, at most STROBE_MAX_AUTH_BYTES. */
);

/**
 * @brief Verify an authenticator.
 * @retval DECAF_SUCCESS The operation applied successfully.
 * @retval DECAF_FAILURE The operation failed because of a
 * bad validator (or because you aren't keyed)
 */
decaf_error_t strobe_verify_auth (
   keccak_strobe_t strobe,  /**< [inout] The Strobe protocol context */
   const unsigned char *in, /**< [in] The authenticator */
   uint16_t len             /**< [in] The length, at most STROBE_MAX_AUTH_BYTES. */
) WARN_UNUSED NONNULL API_VIS;

/**
 * @brief Encrypt bytes from in to out.
 * @warning Doesn't produce an auth tag.
 */
static INLINE UNUSED NONNULL void
strobe_encrypt (
  keccak_strobe_t strobe,  /**< [inout] strobe The Strobe protocol context. */
  unsigned char *out,      /**< [out] The ciphertext. */
  const unsigned char *in, /**< [in] The plaintext. */
  uint16_t len             /**< [in] The length of plaintext and ciphertext. */
);

/**
 * Decrypt bytes from in to out.
 * @warning Doesn't check an auth tag.
 */
static INLINE UNUSED NONNULL void
strobe_decrypt (
  keccak_strobe_t strobe,  /**< [inout] The Strobe protocol context. */
  unsigned char *out,      /**< [out] The plaintext. */
  const unsigned char *in, /**< [in] The ciphertext. */
  uint16_t len             /**< [in] The length of plaintext and ciphertext. */
);

/**
 * @brief Produce a session-bound pseudorandom value.
 *
 * @warning This "prng" value is NOT suitable for
 * refreshing forward secrecy!  It's to replace things
 * like TCP session hash.
 */
static inline void NONNULL strobe_prng (
   keccak_strobe_t strobe, /**< [inout] The Strobe protocol context */
   unsigned char *out,     /**< [out] The output random data. */
   uint16_t len            /**< The length. */
);

/** Respecify Strobe protocol object's crypto. */
void strobe_respec (
   keccak_strobe_t strobe,        /**< [inout] The initialized strobe context. */
   const struct decaf_kparams_s *params /**< [in] Strobe parameter descriptor. */
) NONNULL API_VIS;

/** Securely destroy a STROBE object by overwriting it. */
static INLINE UNUSED NONNULL void
strobe_destroy (
    keccak_strobe_t doomed /**< [in] The object to destroy. */
);

/** @cond internal */

/************************************************************************/
/* Declarations of various constants and operating modes, for extension */
/************************************************************************/   

/** STROBE modes of operation */
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

#define STROBE_FLAG_CLIENT_SENT (1<<8)  /**< Set if the client this message. */
#define STROBE_FLAG_IMPLICIT    (1<<9)  /**< Set if nobody set this message. */
#define STROBE_FLAG_FORGET      (1<<12) /**< After this operation, destroy bytes to prevent rollback. */
/* TODO: maybe just make STROBE heavy non-invertible? */
#define STROBE_FLAG_NO_LENGTH   (1<<15) /**< This operation has an unknown length (for streaming). */

/* After 1<<16, flags don't go to the sponge anymore, they just affect the handling */
#define STROBE_FLAG_RECV        (1<<16) /**< I received this packet, so reverse directions. */
#define STROBE_FLAG_RUN_F       (1<<17) /**< Must run F between control word and data. */
#define STROBE_FLAG_MORE        (1<<18) /**< Set for all operations in an unknown-length streaming operation after the first */
#define STROBE_FLAG_LENGTH_64   (1<<19) /**< Length is a 64-bit word instead of a 16-bit one. */
#define STROBE_FLAG_NONDIR      (STROBE_FLAG_IMPLICIT)

/** Automatic flags implied by the mode */
/* NB: SQUEEZE_R is treated as directional because its' MAC.
 * can of course override by orring in IMPLICIT|NONDIR
 */
#define STROBE_AUTO_FLAGS(_mode)                           \
   (     (((_mode)&1) ? STROBE_FLAG_RUN_F : 0)            \
       | (( ((_mode) & ~2) == STROBE_MODE_ABSORB          \
         ||  (_mode)       == STROBE_MODE_SQUEEZE         \
         ||  (_mode)       == STROBE_MODE_FORGET          \
         ) ? STROBE_FLAG_IMPLICIT|STROBE_FLAG_NONDIR : 0) \
   )

/**@ Define a control word for STROBE protocols. */
#define STROBE_CONTROL_WORD(_name,_id,_mode,_flags) \
   static const uint32_t _name = _id | (_mode<<10) | (_mode<<29) | _flags | STROBE_AUTO_FLAGS(_mode)

STROBE_CONTROL_WORD(STROBE_CW_INIT,               0x00, STROBE_MODE_ABSORB,    0); /**< Initialization with protocol name */
                                             
/* Ciphers */                                    
STROBE_CONTROL_WORD(STROBE_CW_FIXED_KEY,          0x10, STROBE_MODE_ABSORB,    0); /**< Fixed symmetric/preshared key */
STROBE_CONTROL_WORD(STROBE_CW_STATIC_PUB,         0x11, STROBE_MODE_PLAINTEXT, 0); /**< Static public key of other party */
STROBE_CONTROL_WORD(STROBE_CW_DH_EPH,             0x12, STROBE_MODE_PLAINTEXT, 0); /**< DH ephemeral key on the wire */
STROBE_CONTROL_WORD(STROBE_CW_DH_KEY,             0x13, STROBE_MODE_ABSORB,    0); /**< DH shared secret key */
STROBE_CONTROL_WORD(STROBE_CW_PRNG,               0x18, STROBE_MODE_SQUEEZE,   STROBE_FLAG_FORGET); /**< Generate random bits (for PRNG) */
STROBE_CONTROL_WORD(STROBE_CW_SESSION_HASH,       0x19, STROBE_MODE_SQUEEZE,   0); /**< Generate session hash */

/* Reuse for PRNG */
STROBE_CONTROL_WORD(STROBE_CW_PRNG_INITIAL_SEED,  0x10, STROBE_MODE_ABSORB,    STROBE_FLAG_NO_LENGTH); /**< Initial seeding for PRNG */
STROBE_CONTROL_WORD(STROBE_CW_PRNG_RESEED,        0x11, STROBE_MODE_ABSORB,    STROBE_FLAG_NO_LENGTH); /**< Later seeding for PRNG */
STROBE_CONTROL_WORD(STROBE_CW_PRNG_CPU_SEED,      0x12, STROBE_MODE_ABSORB,    0); /**< Seed from CPU-builin RNG */
STROBE_CONTROL_WORD(STROBE_CW_PRNG_USER_SEED,     0x13, STROBE_MODE_ABSORB,    STROBE_FLAG_LENGTH_64); /**< Seed from user */
STROBE_CONTROL_WORD(STROBE_CW_PRNG_PRNG,          0x14, STROBE_MODE_SQUEEZE,   STROBE_FLAG_LENGTH_64 | STROBE_FLAG_FORGET); /**< Call to generate bits */

/* Signatures */                                 
STROBE_CONTROL_WORD(STROBE_CW_SIG_SCHEME,         0x20, STROBE_MODE_ABSORB,    0); /**< Name of the signature scheme we're using. */
STROBE_CONTROL_WORD(STROBE_CW_SIG_PK,             0x21, STROBE_MODE_ABSORB,    0); /**< Public (verification key) */
STROBE_CONTROL_WORD(STROBE_CW_SIG_EPH,            0x22, STROBE_MODE_PLAINTEXT, 0); /**< Schnorr ephemeral. */
STROBE_CONTROL_WORD(STROBE_CW_SIG_CHAL,           0x23, STROBE_MODE_SQUEEZE,   0); /**< Schnorr challenge. */
STROBE_CONTROL_WORD(STROBE_CW_SIG_RESP,           0x24, STROBE_MODE_DUPLEX,    0); /**< Schnoll response. */

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

/** Reverse a keyword because it's being received instead of sent */
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

/***************************************/
/* Implementations of inline functions */
/***************************************/

void strobe_plaintext(keccak_strobe_t strobe, const unsigned char *in, uint16_t len, uint8_t iSent) {
   strobe_transact(
       strobe, NULL, in, len,
       iSent ? STROBE_CW_PAYLOAD_PLAINTEXT
             : strobe_cw_recv(STROBE_CW_PAYLOAD_PLAINTEXT)
   );
}

void strobe_ad(keccak_strobe_t strobe, const unsigned char *in, size_t len) {
    strobe_transact( strobe, NULL, in, len, STROBE_CW_AD_EXPLICIT );
}

void strobe_nonce (keccak_strobe_t strobe, const unsigned char *in, uint16_t len) {
   strobe_transact( strobe, NULL, in, len, STROBE_CW_NONCE_EXPLICIT );
}

void strobe_fixed_key (keccak_strobe_t strobe, const unsigned char *in, uint16_t len) {
   strobe_transact( strobe, NULL, in, len, STROBE_CW_FIXED_KEY );
}

void strobe_dh_key (keccak_strobe_t strobe, const unsigned char *in, uint16_t len) {
   strobe_transact( strobe, NULL, in, len, STROBE_CW_DH_KEY );
}

void strobe_produce_auth (keccak_strobe_t strobe, unsigned char *out, uint16_t len) {
   strobe_transact( strobe, out, NULL, len, STROBE_CW_MAC );
}

void strobe_encrypt (keccak_strobe_t strobe, unsigned char *out, const unsigned char *in, uint16_t len) {
    strobe_transact(strobe, out, in, len, STROBE_CW_PAYLOAD_CIPHERTEXT);
}

void strobe_decrypt(keccak_strobe_t strobe, unsigned char *out, const unsigned char *in, uint16_t len) {
    strobe_transact(strobe, out, in, len, strobe_cw_recv(STROBE_CW_PAYLOAD_CIPHERTEXT));
}

void strobe_prng(keccak_strobe_t strobe, unsigned char *out, uint16_t len) {
    strobe_transact( strobe, out, NULL, len, STROBE_CW_PRNG );
}

void strobe_destroy (keccak_strobe_t doomed) {
    decaf_sponge_destroy(doomed->sponge);
}

/** @endcond */ /* internal */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __DECAF_STROBE_H__ */
