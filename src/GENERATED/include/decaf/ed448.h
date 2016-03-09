/**
 * @file decaf/ed448.h
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief A group of prime order p, based on Ed448-Goldilocks.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */

#ifndef __DECAF_ED448_H__
#define __DECAF_ED448_H__ 1

#include <decaf/decaf_448.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Number of bytes in an EdDSA public key. */
#define DECAF_EDDSA_448_PUBLIC_BYTES 57

/** Number of bytes in an EdDSA private key. */
#define DECAF_EDDSA_448_PRIVATE_BYTES DECAF_EDDSA_448_PUBLIC_BYTES

/** Number of bytes in an EdDSA private key. */
#define DECAF_EDDSA_448_SIGNATURE_BYTES (DECAF_EDDSA_448_PUBLIC_BYTES + DECAF_EDDSA_448_PRIVATE_BYTES)

/** Does EdDSA support contexts? */
#define DECAF_EDDSA_448_SUPPORTS_CONTEXTS 1

/**
 * @brief EdDSA key generation.  This function uses a different (non-Decaf)
 * encoding.
 *
 * @param [out] pubkey The public key.
 * @param [in] privkey The private key.
 */    
void decaf_ed448_derive_public_key (
    uint8_t pubkey[DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t privkey[DECAF_EDDSA_448_PRIVATE_BYTES]
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
void decaf_ed448_sign (
    uint8_t signature[DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t privkey[DECAF_EDDSA_448_PRIVATE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed
#if DECAF_EDDSA_448_SUPPORTS_CONTEXTS
    , const uint8_t *context,
    uint8_t context_len
#endif
) API_VIS __attribute__((nonnull(1,2,3))) NOINLINE;

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
decaf_error_t decaf_ed448_verify (
    const uint8_t signature[DECAF_EDDSA_448_SIGNATURE_BYTES],
    const uint8_t pubkey[DECAF_EDDSA_448_PUBLIC_BYTES],
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed
#if DECAF_EDDSA_448_SUPPORTS_CONTEXTS
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
void decaf_448_point_mul_by_cofactor_and_encode_like_eddsa (
    uint8_t enc[DECAF_EDDSA_448_PUBLIC_BYTES],
    const decaf_448_point_t p
) API_VIS NONNULL NOINLINE;

/**
 * @brief EdDSA point decoding.  Remember that while points on the
 * EdDSA curves have cofactor information, Decaf ignores (quotients
 * out) all cofactor information.
 *
 * @param [out] enc The encoded point.
 * @param [in] p The point.
 */       
decaf_error_t decaf_448_point_decode_like_eddsa_and_ignore_cofactor (
    decaf_448_point_t p,
    const uint8_t enc[DECAF_EDDSA_448_PUBLIC_BYTES]
) API_VIS NONNULL NOINLINE;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __DECAF_ED448_H__ */
