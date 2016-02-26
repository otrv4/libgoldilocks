/**
 * @file decaf/shake.h
 * @copyright Public domain.
 * @author Mike Hamburg
 * @brief SHA2-512
 */

#ifndef __SHA512_H__
#define __SHA512_H__

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h> /* for NULL */

#include <decaf/common.h>

#ifdef __cplusplus
extern "C" {
#endif
    

typedef struct sha512_ctx_s {
    uint64_t state[8];
    uint8_t block[128];
    uint64_t bytesProcessed;
} sha512_ctx_s, sha512_ctx_t[1];

void sha512_init(sha512_ctx_t ctx) NONNULL API_VIS;
void sha512_update(sha512_ctx_t ctx, const uint8_t *message, size_t length) NONNULL API_VIS;
void sha512_final(sha512_ctx_t ctx, uint8_t *out, size_t length) NONNULL API_VIS;

static inline void sha512_destroy(sha512_ctx_t ctx) {
    decaf_bzero(ctx,sizeof(*ctx));
}

static inline void sha512_hash(
    uint8_t *output,
    size_t output_len,
    const uint8_t *message,
    size_t message_len
) {
    sha512_ctx_t ctx;
    sha512_init(ctx);
    sha512_update(ctx,message,message_len);
    sha512_final(ctx,output,output_len);
    sha512_destroy(ctx);
}

#ifdef __cplusplus
} /* extern "C" */
#endif
    
#endif /* __SHA512_H__ */
