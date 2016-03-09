/** @brief A group of prime order p, based on $(iso_to). */

#include <decaf/decaf_$(gf_bits).h>
#include <decaf/shake.h>
#include <decaf/sha512.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Number of bytes in an EdDSA public key. */
#define DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES $((gf_bits)/8 + 1)

/** Number of bytes in an EdDSA private key. */
#define DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES

/** Number of bytes in an EdDSA private key. */
#define DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES (DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES + DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES)

/** Does EdDSA support contexts? */
#define DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS $(eddsa_supports_contexts)
    
/** Prehash context renaming macros. */
#define decaf_ed$(gf_shortname)_prehash_ctx_s   decaf_$(eddsa_hash)_ctx_s
#define decaf_ed$(gf_shortname)_prehash_ctx_t   decaf_$(eddsa_hash)_ctx_t
#define decaf_ed$(gf_shortname)_prehash_update  decaf_$(eddsa_hash)_update
#define decaf_ed$(gf_shortname)_prehash_destroy decaf_$(eddsa_hash)_destroy

/**
 * @brief EdDSA key generation.  This function uses a different (non-Decaf)
 * encoding.
 *
 * @param [out] pubkey The public key.
 * @param [in] privkey The private key.
 */    
void decaf_ed$(gf_shortname)_derive_public_key (
    uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t privkey[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES]
) API_VIS NONNULL NOINLINE;

/**
 * @brief EdDSA signing.
 *
 * @param [out] signature The signature.
 * @param [in] privkey The private key.
 * @param [in] pubkey The public key.
 * @param [in] context A "context" for this signature of up to 255 bytes.
 * @param [in] context_len Length of the context.
 * @param [in] message The message to sign.
 * @param [in] message_len The length of the message.
 * @param [in] prehashed Nonzero if the message is actually the hash of something you want to sign.
 *
 * @warning For Ed25519, it is unsafe to use the same key for both prehashed and non-prehashed
 * messages, at least without some very careful protocol-level disambiguation.  For Ed448 it is
 * safe.  The C++ wrapper is designed to make it harder to screw this up, but this C code gives
 * you no seat belt.
 */  
void decaf_ed$(gf_shortname)_sign (
    uint8_t signature[DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES],
    const uint8_t privkey[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed
#if DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS
    , const uint8_t *context,
    uint8_t context_len
#endif
) API_VIS __attribute__((nonnull(1,2,3))) NOINLINE;

/**
 * @brief EdDSA signing with prehash.
 *
 * @param [out] signature The signature.
 * @param [in] privkey The private key.
 * @param [in] pubkey The public key.
 * @param [in] context A "context" for this signature of up to 255 bytes.  Must be the same as what was used for the prehash.
 * @param [in] context_len Length of the context.
 * @param [in] hash The hash of the message.  This object will not be modified by the call.
 * @param [in] prehashed Nonzero if the message is actually the hash of something you want to sign.
 *
 * @warning For Ed25519, it is unsafe to use the same key for both prehashed and non-prehashed
 * messages, at least without some very careful protocol-level disambiguation.  For Ed448 it is
 * safe.  The C++ wrapper is designed to make it harder to screw this up, but this C code gives
 * you no seat belt.
 */  
void decaf_ed$(gf_shortname)_sign_prehash (
    uint8_t signature[DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES],
    const uint8_t privkey[DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const decaf_ed$(gf_shortname)_prehash_ctx_t hash
#if DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS
    , const uint8_t *context,
    uint8_t context_len
#endif
) API_VIS __attribute__((nonnull(1,2,3,4))) NOINLINE;
    
/**
 * @brief Prehash initialization, with contexts if supported.
 *
 * @param [out] hash The hash object to be initialized.
 * @param [in] context A "context" for this signature of up to 255 bytes.
 * @param [in] context_len Length of the context.
 */
void decaf_ed$(gf_shortname)_prehash_init (
    decaf_ed$(gf_shortname)_prehash_ctx_t hash
#if DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS
    , const uint8_t *context,
    uint8_t context_len
#endif
) API_VIS __attribute__((nonnull(1))) NOINLINE;

/**
 * @brief EdDSA signature verification.
 *
 * Uses the standard (i.e. less-strict) verification formula.
 *
 * @param [in] signature The signature.
 * @param [in] pubkey The public key.
 * @param [in] context A "context" for this signature of up to 255 bytes.
 * @param [in] context_len Length of the context.
 * @param [in] message The message to verify.
 * @param [in] message_len The length of the message.
 * @param [in] prehashed Nonzero if the message is actually the hash of something you want to verify.
 *
 * @warning For Ed25519, it is unsafe to use the same key for both prehashed and non-prehashed
 * messages, at least without some very careful protocol-level disambiguation.  For Ed448 it is
 * safe.  The C++ wrapper is designed to make it harder to screw this up, but this C code gives
 * you no seat belt.
 */
decaf_error_t decaf_ed$(gf_shortname)_verify (
    const uint8_t signature[DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed
#if DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS
    , const uint8_t *context,
    uint8_t context_len
#endif
) API_VIS __attribute__((nonnull(1,2))) NOINLINE;

/**
 * @brief EdDSA signature verification.
 *
 * Uses the standard (i.e. less-strict) verification formula.
 *
 * @param [in] signature The signature.
 * @param [in] pubkey The public key.
 * @param [in] context A "context" for this signature of up to 255 bytes.  Must be the same as what was used for the prehash.
 * @param [in] context_len Length of the context.
 * @param [in] hash The hash of the message.  This object will not be modified by the call.
 * @param [in] prehashed Nonzero if the message is actually the hash of something you want to verify.
 *
 * @warning For Ed25519, it is unsafe to use the same key for both prehashed and non-prehashed
 * messages, at least without some very careful protocol-level disambiguation.  For Ed448 it is
 * safe.  The C++ wrapper is designed to make it harder to screw this up, but this C code gives
 * you no seat belt.
 */
decaf_error_t decaf_ed$(gf_shortname)_verify_prehash (
    const uint8_t signature[DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const decaf_ed$(gf_shortname)_prehash_ctx_t hash
#if DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS
    , const uint8_t *context,
    uint8_t context_len
#endif
) API_VIS __attribute__((nonnull(1,2))) NOINLINE;

/**
 * @brief EdDSA point encoding.  Used internally, exposed externally.
 * Multiplies the point by the current cofactor first.
 *
 * @param [out] enc The encoded point.
 * @param [in] p The point.
 */       
void $(c_ns)_point_mul_by_cofactor_and_encode_like_eddsa (
    uint8_t enc[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES],
    const $(c_ns)_point_t p
) API_VIS NONNULL NOINLINE;

/**
 * @brief EdDSA point decoding.  Remember that while points on the
 * EdDSA curves have cofactor information, Decaf ignores (quotients
 * out) all cofactor information.
 *
 * @param [out] enc The encoded point.
 * @param [in] p The point.
 */       
decaf_error_t $(c_ns)_point_decode_like_eddsa_and_ignore_cofactor (
    $(c_ns)_point_t p,
    const uint8_t enc[DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES]
) API_VIS NONNULL NOINLINE;

#ifdef __cplusplus
} /* extern "C" */
#endif
