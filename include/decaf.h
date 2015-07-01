
#ifndef __DECAF_H__
#define __DECAF_H__ 1

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
#define NONNULL4 __attribute__((nonnull(1,2,3,4)))
#define NONNULL5 __attribute__((nonnull(1,2,3,4,5)))
/** @endcond */

/* Internal word types */
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

    /** NB Success is -1, failure is 0.  TODO: see if people would rather the reverse. */
    static const decaf_bool_t DECAF_SUCCESS = -(decaf_bool_t)1 /*DECAF_TRUE*/,
    	DECAF_FAILURE = 0 /*DECAF_FALSE*/;
    
    #include "decaf_255.h"
    #include "decaf_448.h"


#ifdef __cplusplus
}
#endif


#undef API_VIS
#undef WARN_UNUSED
#undef NOINLINE
#undef NONNULL1
#undef NONNULL2
#undef NONNULL3
#undef NONNULL4
#undef NONNULL5

#endif /* __DECAF_H__ */

