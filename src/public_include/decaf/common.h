/**
 * @file decaf/common.h
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Common utility headers for Decaf library.
 */

#ifndef __DECAF_COMMON_H__
#define __DECAF_COMMON_H__ 1

#include <stdint.h>
#include <sys/types.h>

/* Goldilocks' build flags default to hidden and stripping executables. */
/** @cond internal */
#if defined(DOXYGEN) && !defined(__attribute__)
#define __attribute__((x))
#endif
#define API_VIS __attribute__((visibility("default")))
#define NOINLINE  __attribute__((noinline))
#define WARN_UNUSED __attribute__((warn_unused_result))
#define NONNULL1 __attribute__((nonnull(1)))
#define NONNULL2 __attribute__((nonnull(1,2)))
#define NONNULL3 __attribute__((nonnull(1,2,3)))
#define NONNULL13 __attribute__((nonnull(1,3)))
#define NONNULL4 __attribute__((nonnull(1,2,3,4)))
#define NONNULL5 __attribute__((nonnull(1,2,3,4,5)))
/** @endcond */

/* Internal word types */
/* TODO: decide this internally, per curve, based on how it was built! */
#if (defined(__ILP64__) || defined(__amd64__) || defined(__x86_64__) || (((__UINT_FAST32_MAX__)>>30)>>30)) \
	 && !defined(DECAF_FORCE_32_BIT)
#define DECAF_WORD_BITS 64
typedef uint64_t decaf_word_t, decaf_bool_t;
typedef __uint128_t decaf_dword_t;
#else
#define DECAF_WORD_BITS 32
typedef uint32_t decaf_word_t, decaf_bool_t;
typedef uint64_t decaf_dword_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif
    
/** DECAF_TRUE = -1 so that DECAF_TRUE & x = x */
static const decaf_bool_t DECAF_TRUE = -(decaf_bool_t)1, DECAF_FALSE = 0;

/** NB Success is -1, failure is 0. */
static const decaf_bool_t DECAF_SUCCESS = -(decaf_bool_t)1 /*DECAF_TRUE*/,
	DECAF_FAILURE = 0 /*DECAF_FALSE*/;
    
/**
* @brief Overwrite data with zeros.  Uses memset_s if available.
*/
void decaf_bzero (
    void *data,
    size_t size
) NONNULL1 API_VIS;

/**
* @brief Compare two buffers, returning DECAF_TRUE if they are equal.
*/
decaf_bool_t decaf_memeq (
    const void *data1,
    const void *data2,
    size_t size
) NONNULL2 WARN_UNUSED API_VIS;
    
#ifdef __cplusplus
} /* extern "C" */
#endif
    
#endif /* __DECAF_COMMON_H__ */
