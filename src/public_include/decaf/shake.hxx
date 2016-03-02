/**
 * @file decaf/shake.hxx
 * @copyright
 *   Based on CC0 code by David Leon Gil, 2015 \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief SHA-3-n and SHAKE-n instances, C++ wrapper.
 */

#ifndef __DECAF_SHAKE_HXX__
#define __DECAF_SHAKE_HXX__

#include <decaf/shake.h>
#include <decaf/secure_buffer.hxx>
#include <sys/types.h>

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

/**
 * Hash function derived from Keccak
 * @todo throw exceptions when hash is misused.
 */
class KeccakHash {
protected:
    /** @cond internal */
    /** The C-wrapper sponge state */
    decaf_keccak_sponge_t sp;
    
    /** Initialize from parameters */
    inline KeccakHash(const decaf_kparams_s *params) NOEXCEPT { decaf_sponge_init(sp, params); }
    /** @endcond */
    
public:
    /** Add more data to running hash */
    inline void update(const uint8_t *__restrict__ in, size_t len) NOEXCEPT { decaf_sha3_update(sp,in,len); }

    /** Add more data to running hash, C++ version. */
    inline void update(const Block &s) NOEXCEPT { decaf_sha3_update(sp,s.data(),s.size()); }
    
    /** Add more data, stream version. */
    inline KeccakHash &operator<<(const Block &s) NOEXCEPT { update(s); return *this; }
    
    /** Same as <<. */
    inline KeccakHash &operator+=(const Block &s) NOEXCEPT { return *this << s; }
    
    /** @brief Output bytes from the sponge. */
    inline SecureBuffer output(size_t len) throw(std::bad_alloc, LengthException) {
        if (len > max_output_size()) throw LengthException();
        SecureBuffer buffer(len);
        if (DECAF_SUCCESS != decaf_sha3_output(sp,buffer.data(),len)) {
            throw LengthException();
        }
        return buffer;
    }
    
    /** @brief Output bytes from the sponge. */
    inline SecureBuffer final(size_t len) throw(std::bad_alloc, LengthException) {
        if (len > max_output_size()) throw LengthException();
        SecureBuffer buffer(len);
        if (DECAF_SUCCESS != decaf_sha3_final(sp,buffer.data(),len)) {
            throw LengthException();
        }
        return buffer;
    }

    /** @brief Output bytes from the sponge.  Throw LengthException if you've
     * output too many bytes from a SHA-3 instance.
     */
    inline void output(Buffer b) throw(LengthException) {
        if (DECAF_SUCCESS != decaf_sha3_output(sp,b.data(),b.size())) {
            throw LengthException();
        }
    }
    
    /**  @brief Output bytes from the sponge and reinitialize it.  Throw
     * LengthException if you've output too many bytes from a SHA3 instance.
     */
    inline void final(Buffer b) throw(LengthException) {
        if (DECAF_SUCCESS != decaf_sha3_final(sp,b.data(),b.size())) {
            throw LengthException();
        }
    }
    
    /** @brief Return the sponge's default output size. */
    inline size_t default_output_size() const NOEXCEPT {
        return decaf_sponge_default_output_bytes(sp);
    }
    
    /** @brief Return the sponge's maximum output size. */
    inline size_t max_output_size() const NOEXCEPT {
        return decaf_sponge_max_output_bytes(sp);
    }
    
    /** Output the default number of bytes. */
    inline SecureBuffer output() throw(std::bad_alloc,LengthException) {
        return output(default_output_size());
    }
    
    /** Output the default number of bytes, and reset hash. */
    inline SecureBuffer final() throw(std::bad_alloc,LengthException) {
        return final(default_output_size());
    }

    /** Reset the hash to the empty string */
    inline void reset() NOEXCEPT { decaf_sha3_reset(sp); }
    
    /** Destructor zeroizes state */
    inline ~KeccakHash() NOEXCEPT { decaf_sponge_destroy(sp); }
};

/** Fixed-output-length SHA3 */
template<int bits> class SHA3 : public KeccakHash {
private:
    /** Get the parameter template block for this hash */
    static inline const struct decaf_kparams_s *get_params();
    
public:
    /** Number of bytes of output */
    static const size_t MAX_OUTPUT_BYTES = bits/8;
    
    /** Number of bytes of output */
    static const size_t DEFAULT_OUTPUT_BYTES = bits/8;
    
    /** Initializer */
    inline SHA3() NOEXCEPT : KeccakHash(get_params()) {}

    /** Hash bytes with this SHA3 instance.
     * @throw LengthException if nbytes > MAX_OUTPUT_BYTES
     */
    static inline SecureBuffer hash(const Block &b, size_t nbytes = MAX_OUTPUT_BYTES) throw(std::bad_alloc, LengthException) {
        if (nbytes > MAX_OUTPUT_BYTES) {
            throw LengthException();
        }
        SHA3 s; s += b; return s.output(nbytes);
    }
};

/** Variable-output-length SHAKE */
template<int bits>
class SHAKE : public KeccakHash {
private:
    /** Get the parameter template block for this hash */
    static inline const struct decaf_kparams_s *get_params();
    
public:
    /** Number of bytes of output */
#if __cplusplus >= 201103L
    static const size_t MAX_OUTPUT_BYTES = SIZE_MAX;
#else
    static const size_t MAX_OUTPUT_BYTES = (size_t)-1;
#endif

    /** Default number of bytes to output */
    static const size_t DEFAULT_OUTPUT_BYTES = bits/4;
    
    /** Initializer */
    inline SHAKE() NOEXCEPT : KeccakHash(get_params()) {}
    
    /** Hash bytes with this SHAKE instance */
    static inline SecureBuffer hash(const Block &b, size_t outlen) throw(std::bad_alloc) {
        SHAKE s; s += b; return s.output(outlen);
    }
};

/** @cond internal */
template<> inline const struct decaf_kparams_s *SHAKE<128>::get_params() { return &DECAF_SHAKE128_params_s; }
template<> inline const struct decaf_kparams_s *SHAKE<256>::get_params() { return &DECAF_SHAKE256_params_s; }
template<> inline const struct decaf_kparams_s *SHA3<224>::get_params() { return  &DECAF_SHA3_224_params_s; }
template<> inline const struct decaf_kparams_s *SHA3<256>::get_params() { return  &DECAF_SHA3_256_params_s; }
template<> inline const struct decaf_kparams_s *SHA3<384>::get_params() { return  &DECAF_SHA3_384_params_s; }
template<> inline const struct decaf_kparams_s *SHA3<512>::get_params() { return  &DECAF_SHA3_512_params_s; }
/** @endcond */
  
} /* namespace decaf */

#undef NOEXCEPT
#undef DELETE

#endif /* __DECAF_SHAKE_HXX__ */
