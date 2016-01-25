

/**
 * @file decaf/strobe.hxx
 * @copyright
 *   Based on CC0 code by David Leon Gil, 2015 \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Sponge RNG instances, C++ wrapper.
 * @warning The guts of this are subject to change.  Please don't implement
 * anything that depends on the deterministic RNG being stable across versions
 * of this library.
 */

#ifndef __DECAF_SPONGERNG_HXX__
#define __DECAF_SPONGERNG_HXX__

#include <decaf/spongerng.h>

#include <string>
#include <sys/types.h>
#include <errno.h>

/** @cond internal */
#if __cplusplus >= 201103L
#define NOEXCEPT noexcept
#define DELETE = delete
#else
#define NOEXCEPT throw()
#define DELETE
#endif
/** @endcond */

namespace decaf {

/** Sponge-based random-number generator */
class SpongeRng : public Rng {
private:
    /** C wrapped object */
    keccak_prng_t sp;
    
public:
    /** Exception thrown when The RNG fails (to seed itself) */
    class RngException : public std::exception {
    private:
        /** @cond internal */
        const char *const what_;
        /** @endcond */
    public:
        const int err_code; /**< errno that caused the reseed to fail. */
        const char *what() const NOEXCEPT { return what_; } /**< Description of exception. */
        RngException(int err_code, const char *what_) NOEXCEPT : what_(what_), err_code(err_code) {} /**< Construct */
    };
    
    /** Initialize, deterministically by default, from block */
    inline SpongeRng( const Block &in, bool deterministic = true ) {
        spongerng_init_from_buffer(sp,in.data(),in.size(),deterministic);
    }
    
    /** Initialize, non-deterministically by default, from C/C++ filename */
    inline SpongeRng( const std::string &in = "/dev/urandom", size_t len = 32, bool deterministic = false )
        throw(RngException) {
        decaf_error_t ret = spongerng_init_from_file(sp,in.c_str(),len,deterministic);
        if (!decaf_successful(ret)) {
            throw RngException(errno, "Couldn't load from file");
        }
    }
    
    /** Stir in new data */
    inline void stir( const Block &data ) NOEXCEPT {
        spongerng_stir(sp,data.data(),data.size());
    }
    
    /** Securely destroy by overwriting state. */
    inline ~SpongeRng() NOEXCEPT { spongerng_destroy(sp); }
    
    using Rng::read;
    
    /** Read data to a buffer. */
    virtual inline void read(Buffer buffer) NOEXCEPT
#if __cplusplus >= 201103L
        final
#endif
        { spongerng_next(sp,buffer.data(),buffer.size()); }
    
private:
    SpongeRng(const SpongeRng &) DELETE;
    SpongeRng &operator=(const SpongeRng &) DELETE;
};
/**@endcond*/
  
} /* namespace decaf */

#undef NOEXCEPT
#undef DELETE

#endif /* __DECAF_SPONGERNG_HXX__ */
