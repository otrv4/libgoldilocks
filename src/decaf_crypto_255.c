/**
 * @cond internal
 * @file decaf_crypto_255.c
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Example Decaf crypto routines, 255-bit version.
 */

#include <decaf/crypto_255.h>
#include <string.h>

static const unsigned int DECAF_255_SCALAR_OVERKILL_BYTES = DECAF_255_SCALAR_BYTES + 8;

void decaf_255_derive_private_key (
    decaf_255_private_key_t priv,
    const decaf_255_symmetric_key_t proto
) {
    const char *magic = "decaf::derive_255_private_key"; /* TODO: canonicalize and freeze */
    uint8_t encoded_scalar[DECAF_255_SCALAR_OVERKILL_BYTES];
    decaf_255_point_t pub;
    
    keccak_strobe_t strobe;
    strobe_init(strobe, &STROBE_256, magic, 0);
    strobe_fixed_key(strobe, proto, sizeof(decaf_255_symmetric_key_t));
    strobe_prng(strobe, encoded_scalar, sizeof(encoded_scalar));
    strobe_destroy(strobe);
    
    memcpy(priv->sym, proto, sizeof(decaf_255_symmetric_key_t));
    decaf_255_scalar_decode_long(priv->secret_scalar, encoded_scalar, sizeof(encoded_scalar));
    
    decaf_255_precomputed_scalarmul(pub, decaf_255_precomputed_base, priv->secret_scalar);
    decaf_255_point_encode(priv->pub, pub);
    
    decaf_bzero(encoded_scalar, sizeof(encoded_scalar));
}

void
decaf_255_destroy_private_key (
    decaf_255_private_key_t priv
)  {
    decaf_bzero((void*)priv, sizeof(decaf_255_private_key_t));
}

void decaf_255_private_to_public (
    decaf_255_public_key_t pub,
    const decaf_255_private_key_t priv
) {
    memcpy(pub, priv->pub, sizeof(decaf_255_public_key_t));
}

static const uint16_t SHARED_SECRET_MAX_BLOCK_SIZE = 1<<12; /* TODO: standardize and freeze */

decaf_error_t
decaf_255_shared_secret (
    uint8_t *shared,
    size_t shared_bytes,
    const decaf_255_private_key_t my_privkey,
    const decaf_255_public_key_t your_pubkey,
    int me_first
) {
    const char *magic = "decaf::decaf_255_shared_secret"; /* TODO: canonicalize and freeze */
    keccak_strobe_t strobe;
    strobe_init(strobe, &STROBE_256, magic, 0);
    
    uint8_t ss_ser[DECAF_255_SER_BYTES];
    
    if (me_first) {
        strobe_ad(strobe,my_privkey->pub,sizeof(decaf_255_public_key_t));
        strobe_ad(strobe,your_pubkey,sizeof(decaf_255_public_key_t));
    } else {
        strobe_ad(strobe,your_pubkey,sizeof(decaf_255_public_key_t));
        strobe_ad(strobe,my_privkey->pub,sizeof(decaf_255_public_key_t));
    }
    decaf_error_t ret = decaf_255_direct_scalarmul(
        ss_ser, your_pubkey, my_privkey->secret_scalar, DECAF_FALSE, DECAF_TRUE
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
decaf_255_sign_strobe (
    keccak_strobe_t strobe,
    decaf_255_signature_t sig,
    const decaf_255_private_key_t priv
) {
    uint8_t overkill[DECAF_255_SCALAR_OVERKILL_BYTES];
    decaf_255_point_t point;
    decaf_255_scalar_t nonce, challenge;
    
    /* Stir pubkey */
    strobe_transact(strobe,NULL,priv->pub,sizeof(decaf_255_public_key_t),STROBE_CW_SIG_PK);
    
    /* Derive nonce */
    keccak_strobe_t strobe2;
    memcpy(strobe2,strobe,sizeof(strobe2));
    strobe_fixed_key(strobe2,priv->sym,sizeof(decaf_255_symmetric_key_t));
    strobe_prng(strobe2,overkill,sizeof(overkill));
    strobe_destroy(strobe2);
    
    decaf_255_scalar_decode_long(nonce, overkill, sizeof(overkill));
    decaf_255_precomputed_scalarmul(point, decaf_255_precomputed_base, nonce);
    decaf_255_point_encode(sig, point);
    

    /* Derive challenge */
    strobe_transact(strobe,NULL,sig,DECAF_255_SER_BYTES,STROBE_CW_SIG_EPH);
    strobe_transact(strobe,overkill,NULL,sizeof(overkill),STROBE_CW_SIG_CHAL);
    decaf_255_scalar_decode_long(challenge, overkill, sizeof(overkill));
    
    /* Respond */
    decaf_255_scalar_mul(challenge, challenge, priv->secret_scalar);
    decaf_255_scalar_sub(nonce, nonce, challenge);
    
    /* Save results */
    decaf_255_scalar_encode(overkill, nonce);
    strobe_transact(strobe,&sig[DECAF_255_SER_BYTES],overkill,DECAF_255_SCALAR_BYTES,STROBE_CW_SIG_RESP);
    
    /* Clean up */
    decaf_255_scalar_destroy(nonce);
    decaf_255_scalar_destroy(challenge);
    decaf_bzero(overkill,sizeof(overkill));
}

decaf_error_t
decaf_255_verify_strobe (
    keccak_strobe_t strobe,
    const decaf_255_signature_t sig,
    const decaf_255_public_key_t pub
) {
    decaf_bool_t ret;
    
    uint8_t overkill[DECAF_255_SCALAR_OVERKILL_BYTES];
    decaf_255_point_t point, pubpoint;
    decaf_255_scalar_t challenge, response;
    
    /* Stir pubkey */
    strobe_transact(strobe,NULL,pub,sizeof(decaf_255_public_key_t),STROBE_CW_SIG_PK);
    
    /* Derive nonce */
    strobe_transact(strobe,NULL,sig,DECAF_255_SER_BYTES,STROBE_CW_SIG_EPH);
    ret = decaf_successful( decaf_255_point_decode(point, sig, DECAF_TRUE) );
    
    /* Derive challenge */
    strobe_transact(strobe,overkill,NULL,sizeof(overkill),STROBE_CW_SIG_CHAL);
    decaf_255_scalar_decode_long(challenge, overkill, sizeof(overkill));
    
    /* Decode response */
    strobe_transact(strobe,overkill,&sig[DECAF_255_SER_BYTES],DECAF_255_SCALAR_BYTES,STROBE_CW_SIG_RESP);
    ret &= decaf_successful( decaf_255_scalar_decode(response, overkill) );
    ret &= decaf_successful( decaf_255_point_decode(pubpoint, pub, DECAF_FALSE) );

    decaf_255_base_double_scalarmul_non_secret (
        pubpoint, response, pubpoint, challenge
    );

    ret &= decaf_255_point_eq(pubpoint, point);
    
    /* Nothing here is secret, so don't do these things:
        decaf_bzero(overkill,sizeof(overkill));
        decaf_255_point_destroy(point);
        decaf_255_point_destroy(pubpoint);
        decaf_255_scalar_destroy(challenge);
        decaf_255_scalar_destroy(response);
    */
    
    return decaf_succeed_if(ret);
}

void
decaf_255_sign (
    decaf_255_signature_t sig,
    const decaf_255_private_key_t priv,
    const unsigned char *message,
    size_t message_len
) {
    keccak_strobe_t ctx;
    strobe_init(ctx,&STROBE_256,"decaf::decaf_255_sign",0); /* TODO: canonicalize and freeze */
    strobe_transact(ctx, NULL, message, message_len, STROBE_CW_STREAMING_PLAINTEXT);
    decaf_255_sign_strobe(ctx, sig, priv);
    strobe_destroy(ctx);
}

decaf_error_t
decaf_255_verify (
    const decaf_255_signature_t sig,
    const decaf_255_public_key_t pub,
    const unsigned char *message,
    size_t message_len
) {
    keccak_strobe_t ctx;
    strobe_init(ctx,&STROBE_256,"decaf::decaf_255_sign",0); /* TODO: canonicalize and freeze */
    strobe_transact(ctx, NULL, message, message_len, STROBE_CW_STREAMING_PLAINTEXT);
    decaf_error_t ret = decaf_255_verify_strobe(ctx, sig, pub);
    strobe_destroy(ctx);
    return ret;
}
