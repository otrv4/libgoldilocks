/**
 * @file curve25519/crypto.c
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @cond internal
 * @brief Example Decaf crypto routines
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */
#include <decaf/crypto.h>
#include <string.h>

#define API_NAME "decaf_255"
#define API_NS(_id) decaf_255_##_id
#define SCALAR_BITS DECAF_255_SCALAR_BITS
#define SCALAR_BYTES ((SCALAR_BITS + 7)/8)
#define SER_BYTES DECAF_255_SER_BYTES

 /* TODO: canonicalize and freeze the STROBE constants in this file
  * (and STROBE itself for that matter)
  */
static const char *DERIVE_MAGIC = API_NAME"::derive_private_key";
static const char *SIGN_MAGIC = API_NAME"::sign";
static const char *SHARED_SECRET_MAGIC = API_NAME"::shared_secret";
static const uint16_t SHARED_SECRET_MAX_BLOCK_SIZE = 1<<12;
static const unsigned int SCALAR_OVERKILL_BYTES = SCALAR_BYTES + 8;

void API_NS(derive_private_key) (
    API_NS(private_key_t) priv,
    const API_NS(symmetric_key_t) proto
) {
    uint8_t encoded_scalar[SCALAR_OVERKILL_BYTES];
    API_NS(point_t) pub;
    
    keccak_strobe_t strobe;
    strobe_init(strobe, &STROBE_256, DERIVE_MAGIC, 0);
    strobe_fixed_key(strobe, proto, sizeof(API_NS(symmetric_key_t)));
    strobe_prng(strobe, encoded_scalar, sizeof(encoded_scalar));
    strobe_destroy(strobe);
    
    memcpy(priv->sym, proto, sizeof(API_NS(symmetric_key_t)));
    API_NS(scalar_decode_long)(priv->secret_scalar, encoded_scalar, sizeof(encoded_scalar));
    
    API_NS(precomputed_scalarmul)(pub, API_NS(precomputed_base), priv->secret_scalar);
    API_NS(point_encode)(priv->pub, pub);
    
    decaf_bzero(encoded_scalar, sizeof(encoded_scalar));
}

void
API_NS(destroy_private_key) (
    API_NS(private_key_t) priv
)  {
    decaf_bzero((void*)priv, sizeof(API_NS(private_key_t)));
}

void API_NS(private_to_public) (
    API_NS(public_key_t) pub,
    const API_NS(private_key_t) priv
) {
    memcpy(pub, priv->pub, sizeof(API_NS(public_key_t)));
}

/* Performance vs consttime tuning.
 * Specifying true here might give better DOS resistance in certain corner
 * cases.  Specifying false gives a tighter result in test_ct.
 */
#ifndef DECAF_CRYPTO_SHARED_SECRET_SHORT_CIRUIT
#define DECAF_CRYPTO_SHARED_SECRET_SHORT_CIRUIT DECAF_FALSE
#endif

decaf_error_t
API_NS(shared_secret) (
    uint8_t *shared,
    size_t shared_bytes,
    const API_NS(private_key_t) my_privkey,
    const API_NS(public_key_t) your_pubkey,
    int me_first
) {
    keccak_strobe_t strobe;
    strobe_init(strobe, &STROBE_256, SHARED_SECRET_MAGIC, 0);
    
    uint8_t ss_ser[SER_BYTES];
    
    if (me_first) {
        strobe_ad(strobe,my_privkey->pub,sizeof(API_NS(public_key_t)));
        strobe_ad(strobe,your_pubkey,sizeof(API_NS(public_key_t)));
    } else {
        strobe_ad(strobe,your_pubkey,sizeof(API_NS(public_key_t)));
        strobe_ad(strobe,my_privkey->pub,sizeof(API_NS(public_key_t)));
    }
    decaf_error_t ret = API_NS(direct_scalarmul)(
        ss_ser, your_pubkey, my_privkey->secret_scalar, DECAF_FALSE,
        DECAF_CRYPTO_SHARED_SECRET_SHORT_CIRUIT
    );
    
    strobe_transact(strobe,NULL,ss_ser,sizeof(ss_ser),STROBE_CW_DH_KEY);
    
    while (shared_bytes) {
        uint16_t cando = (shared_bytes > SHARED_SECRET_MAX_BLOCK_SIZE)
                       ? SHARED_SECRET_MAX_BLOCK_SIZE : shared_bytes;
        strobe_prng(strobe,shared,cando);
        shared_bytes -= cando;
        shared += cando;
    }

    strobe_destroy(strobe);
    decaf_bzero(ss_ser, sizeof(ss_ser));
    
    return ret;
}

void
API_NS(sign_strobe) (
    keccak_strobe_t strobe,
    API_NS(signature_t) sig,
    const API_NS(private_key_t) priv
) {
    uint8_t overkill[SCALAR_OVERKILL_BYTES];
    API_NS(point_t) point;
    API_NS(scalar_t) nonce, challenge;
    
    /* Stir pubkey */
    strobe_transact(strobe,NULL,priv->pub,sizeof(API_NS(public_key_t)),STROBE_CW_SIG_PK);
    
    /* Derive nonce */
    keccak_strobe_t strobe2;
    memcpy(strobe2,strobe,sizeof(strobe2));
    strobe_fixed_key(strobe2,priv->sym,sizeof(API_NS(symmetric_key_t)));
    strobe_prng(strobe2,overkill,sizeof(overkill));
    strobe_destroy(strobe2);
    
    API_NS(scalar_decode_long)(nonce, overkill, sizeof(overkill));
    API_NS(precomputed_scalarmul)(point, API_NS(precomputed_base), nonce);
    API_NS(point_encode)(sig, point);
    

    /* Derive challenge */
    strobe_transact(strobe,NULL,sig,SER_BYTES,STROBE_CW_SIG_EPH);
    strobe_transact(strobe,overkill,NULL,sizeof(overkill),STROBE_CW_SIG_CHAL);
    API_NS(scalar_decode_long)(challenge, overkill, sizeof(overkill));
    
    /* Respond */
    API_NS(scalar_mul)(challenge, challenge, priv->secret_scalar);
    API_NS(scalar_sub)(nonce, nonce, challenge);
    
    /* Save results */
    API_NS(scalar_encode)(overkill, nonce);
    strobe_transact(strobe,&sig[SER_BYTES],overkill,SCALAR_BYTES,STROBE_CW_SIG_RESP);
    
    /* Clean up */
    API_NS(scalar_destroy)(nonce);
    API_NS(scalar_destroy)(challenge);
    decaf_bzero(overkill,sizeof(overkill));
}

decaf_error_t
API_NS(verify_strobe) (
    keccak_strobe_t strobe,
    const API_NS(signature_t) sig,
    const API_NS(public_key_t) pub
) {
    decaf_bool_t ret;
    
    uint8_t overkill[SCALAR_OVERKILL_BYTES];
    API_NS(point_t) point, pubpoint;
    API_NS(scalar_t) challenge, response;
    
    /* Stir pubkey */
    strobe_transact(strobe,NULL,pub,sizeof(API_NS(public_key_t)),STROBE_CW_SIG_PK);
    
    /* Derive nonce */
    strobe_transact(strobe,NULL,sig,SER_BYTES,STROBE_CW_SIG_EPH);
    ret = decaf_successful( API_NS(point_decode)(point, sig, DECAF_TRUE) );
    
    /* Derive challenge */
    strobe_transact(strobe,overkill,NULL,sizeof(overkill),STROBE_CW_SIG_CHAL);
    API_NS(scalar_decode_long)(challenge, overkill, sizeof(overkill));
    
    /* Decode response */
    strobe_transact(strobe,overkill,&sig[SER_BYTES],SCALAR_BYTES,STROBE_CW_SIG_RESP);
    ret &= decaf_successful( API_NS(scalar_decode)(response, overkill) );
    ret &= decaf_successful( API_NS(point_decode)(pubpoint, pub, DECAF_FALSE) );

    API_NS(base_double_scalarmul_non_secret) (
        pubpoint, response, pubpoint, challenge
    );

    ret &= API_NS(point_eq)(pubpoint, point);
    
    /* Nothing here is secret, so don't do these things:
        decaf_bzero(overkill,sizeof(overkill));
        API_NS(point_destroy)(point);
        API_NS(point_destroy)(pubpoint);
        API_NS(scalar_destroy)(challenge);
        API_NS(scalar_destroy)(response);
    */
    
    return decaf_succeed_if(ret);
}

void
API_NS(sign) (
    API_NS(signature_t) sig,
    const API_NS(private_key_t) priv,
    const unsigned char *message,
    size_t message_len
) {
    keccak_strobe_t ctx;
    strobe_init(ctx,&STROBE_256,SIGN_MAGIC,0);
    strobe_transact(ctx, NULL, message, message_len, STROBE_CW_STREAMING_PLAINTEXT);
    API_NS(sign_strobe)(ctx, sig, priv);
    strobe_destroy(ctx);
}

decaf_error_t
API_NS(verify) (
    const API_NS(signature_t) sig,
    const API_NS(public_key_t) pub,
    const unsigned char *message,
    size_t message_len
) {
    keccak_strobe_t ctx;
    strobe_init(ctx,&STROBE_256,SIGN_MAGIC,0);
    strobe_transact(ctx, NULL, message, message_len, STROBE_CW_STREAMING_PLAINTEXT);
    decaf_error_t ret = API_NS(verify_strobe)(ctx, sig, pub);
    strobe_destroy(ctx);
    return ret;
}
