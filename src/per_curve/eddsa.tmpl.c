/**
 * @cond internal
 * @brief EdDSA routines.
 */

#include "decaf.h"
#include "decaf/shake.h"
#include "word.h"
#include <string.h>

#define API_NAME "$(c_ns)"
#define API_NS(_id) $(c_ns)_##_id

static void clamp(
    uint8_t secret_scalar_ser[$(C_NS)_EDDSA_PRIVATE_BYTES]
) {
    /* Blarg */
    secret_scalar_ser[0] &= -$(cofactor);
    uint8_t hibit = (1<<$(gf_bits % 8))>>1;
    secret_scalar_ser[$(C_NS)_EDDSA_PRIVATE_BYTES - 1] &= -hibit;
    secret_scalar_ser[$(C_NS)_EDDSA_PRIVATE_BYTES - 1] |= hibit;
    if (hibit == 0) secret_scalar_ser[$(C_NS)_EDDSA_PRIVATE_BYTES - 2] |= 0x80;
}

void API_NS(eddsa_derive_public_key) (
    uint8_t pubkey[$(C_NS)_EDDSA_PUBLIC_BYTES],
    const uint8_t privkey[$(C_NS)_EDDSA_PRIVATE_BYTES]
) {
    /* only this much used for keygen */
    uint8_t secret_scalar_ser[$(C_NS)_EDDSA_PRIVATE_BYTES];
    
    shake256_hash(
        secret_scalar_ser,
        sizeof(secret_scalar_ser),
        privkey,
        $(C_NS)_EDDSA_PRIVATE_BYTES
    );
    clamp(secret_scalar_ser);
        
    API_NS(scalar_t) secret_scalar;
    API_NS(scalar_decode_long)(secret_scalar, secret_scalar_ser, sizeof(secret_scalar_ser));
    /* TODO: write documentation for why (due to isogenies) this needs to be quartered */
    API_NS(scalar_sub)(secret_scalar,API_NS(scalar_zero),secret_scalar);
    API_NS(scalar_halve)(secret_scalar,secret_scalar);
    API_NS(scalar_halve)(secret_scalar,secret_scalar);
    
    API_NS(point_t) p;
    API_NS(precomputed_scalarmul)(p,API_NS(precomputed_base),secret_scalar);
    
    API_NS(point_encode_like_eddsa)(pubkey, p);
        
    /* Cleanup */
    API_NS(scalar_destroy)(secret_scalar);
    API_NS(point_destroy)(p);
    decaf_bzero(secret_scalar_ser, sizeof(secret_scalar_ser));
}

static const char *domS = "SigEd448";

void API_NS(eddsa_sign) (
    uint8_t signature[$(C_NS)_EDDSA_SIGNATURE_BYTES],
    const uint8_t privkey[$(C_NS)_EDDSA_PRIVATE_BYTES],
    const uint8_t pubkey[$(C_NS)_EDDSA_PUBLIC_BYTES],
    const uint8_t *context,
    uint8_t context_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed
) {
    /* FIXME: of course, need a different hash for Curve25519 */
    
    API_NS(scalar_t) secret_scalar;
    shake256_ctx_t shake;
    const uint8_t dom[2] = {1+word_is_zero(prehashed), context_len};
    {
        /* Schedule the secret key */
        struct {
            uint8_t secret_scalar_ser[$(C_NS)_EDDSA_PRIVATE_BYTES];
            uint8_t seed[$(C_NS)_EDDSA_PRIVATE_BYTES];
        } __attribute__((packed)) expanded;
        shake256_hash(
            (uint8_t *)&expanded,
            sizeof(expanded),
            privkey,
            $(C_NS)_EDDSA_PRIVATE_BYTES
        );
        clamp(expanded.secret_scalar_ser);   
        API_NS(scalar_decode_long)(secret_scalar, expanded.secret_scalar_ser, sizeof(expanded.secret_scalar_ser));
    
        /* Hash to create the nonce */
        shake256_init(shake);
        shake256_update(shake,(const unsigned char *)domS, strlen(domS));
        shake256_update(shake,dom,2);
        shake256_update(shake,context,context_len);
        shake256_update(shake,expanded.seed,sizeof(expanded.seed));
        shake256_update(shake,message,message_len);
        decaf_bzero(&expanded, sizeof(expanded));
    }
    
    /* Decode the nonce */
    API_NS(scalar_t) nonce_scalar;
    {
        uint8_t nonce[2*$(C_NS)_EDDSA_PRIVATE_BYTES];
        shake256_final(shake,nonce,sizeof(nonce));
        API_NS(scalar_decode_long)(nonce_scalar, nonce, sizeof(nonce));
        decaf_bzero(nonce, sizeof(nonce));
    }
    
    uint8_t nonce_point[$(C_NS)_EDDSA_PUBLIC_BYTES] = {0};
    {
        /* Scalarmul to create the nonce-point */
        API_NS(scalar_t) nonce_scalar_2;
        API_NS(scalar_halve)(nonce_scalar_2, nonce_scalar);
        API_NS(scalar_halve)(nonce_scalar_2, nonce_scalar_2);
        API_NS(scalar_sub)(nonce_scalar_2,API_NS(scalar_zero),nonce_scalar_2);
        API_NS(point_t) p;
        API_NS(precomputed_scalarmul)(p,API_NS(precomputed_base),nonce_scalar_2);
        API_NS(point_encode_like_eddsa)(nonce_point, p);
        API_NS(point_destroy)(p);
        API_NS(scalar_destroy)(nonce_scalar_2);
    }
    
    API_NS(scalar_t) challenge_scalar;
    {
        /* Compute the challenge */
        shake256_init(shake);
        shake256_update(shake,(const unsigned char *)domS, strlen(domS));
        shake256_update(shake,dom,2);
        shake256_update(shake,context,context_len);
        shake256_update(shake,nonce_point,sizeof(nonce_point));
        shake256_update(shake,pubkey,$(C_NS)_EDDSA_PUBLIC_BYTES);
        shake256_update(shake,message,message_len);
        uint8_t challenge[2*$(C_NS)_EDDSA_PRIVATE_BYTES];
        shake256_final(shake,challenge,sizeof(challenge));
        shake256_destroy(shake);
        API_NS(scalar_decode_long)(challenge_scalar,challenge,sizeof(challenge));
        decaf_bzero(challenge,sizeof(challenge));
    }
    
    API_NS(scalar_mul)(challenge_scalar,challenge_scalar,secret_scalar);
    API_NS(scalar_add)(challenge_scalar,challenge_scalar,nonce_scalar);
    
    decaf_bzero(signature,$(C_NS)_EDDSA_SIGNATURE_BYTES);
    memcpy(signature,nonce_point,sizeof(nonce_point));
    API_NS(scalar_encode)(&signature[$(C_NS)_EDDSA_PUBLIC_BYTES],challenge_scalar);
    
    API_NS(scalar_destroy)(secret_scalar);
    API_NS(scalar_destroy)(nonce_scalar);
    API_NS(scalar_destroy)(challenge_scalar);
}


decaf_error_t API_NS(eddsa_verify) (
    const uint8_t signature[$(C_NS)_EDDSA_SIGNATURE_BYTES],
    const uint8_t pubkey[$(C_NS)_EDDSA_PUBLIC_BYTES],
    const uint8_t *context,
    uint8_t context_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t prehashed
) { 
    API_NS(point_t) pk_point, r_point;
    decaf_error_t error = API_NS(point_decode_like_eddsa)(pk_point,pubkey);
    if (DECAF_SUCCESS != error) { return error; }
    
    error = API_NS(point_decode_like_eddsa)(r_point,signature);
    if (DECAF_SUCCESS != error) { return error; }
    
    API_NS(scalar_t) challenge_scalar;
    {
        /* Compute the challenge */
        shake256_ctx_t shake;
        const uint8_t dom[2] = {1+word_is_zero(prehashed), context_len};
        shake256_init(shake);
        shake256_update(shake,(const unsigned char *)domS, strlen(domS));
        shake256_update(shake,dom,2);
        shake256_update(shake,context,context_len);
        shake256_update(shake,signature,$(C_NS)_EDDSA_PUBLIC_BYTES);
        shake256_update(shake,pubkey,$(C_NS)_EDDSA_PUBLIC_BYTES);
        shake256_update(shake,message,message_len);
        uint8_t challenge[2*$(C_NS)_EDDSA_PRIVATE_BYTES];
        shake256_final(shake,challenge,sizeof(challenge));
        shake256_destroy(shake);
        API_NS(scalar_decode_long)(challenge_scalar,challenge,sizeof(challenge));
        decaf_bzero(challenge,sizeof(challenge));
    }
    API_NS(scalar_sub)(challenge_scalar, API_NS(scalar_zero), challenge_scalar);
    
    API_NS(scalar_t) response_scalar;
    API_NS(scalar_decode_long)(
        response_scalar,
        &signature[$(C_NS)_EDDSA_PUBLIC_BYTES],
        $(C_NS)_EDDSA_PRIVATE_BYTES
    );
    API_NS(scalar_sub)(response_scalar, API_NS(scalar_zero), response_scalar); /* TODO because nega-base point */
    
    /* pk_point = -c(x(P)) + (cx + k)G = kG */
    API_NS(base_double_scalarmul_non_secret)(
        pk_point,
        response_scalar,
        pk_point,
        challenge_scalar
    );
    return decaf_succeed_if(API_NS(point_eq(pk_point,r_point)));
}
