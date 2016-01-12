/**
 * @file decaf/shake.hxx
 * @copyright
 *   Based on CC0 code by David Leon Gil, 2015 \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief SHA-3-n and SHAKE-n instances, C++ wrapper.
 * @warning EXPERIMENTAL!  The names, parameter orders etc are likely to change.
 */

#ifndef __SHAKE_HXX__
#define __SHAKE_HXX__

#include <decaf/shake.h>
#include <decaf/strobe.h> /* TODO remove */
#include <decaf/spongerng.h> /* TODO remove */

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

/**
 * Hash function derived from Keccak
 * @todo throw exceptions when hash is misused.
 */
class KeccakHash {
protected:
    /** @cond internal */
    /** The C-wrapper sponge state */
    keccak_sponge_t sp;
    
    /** Initialize from parameters */
    inline KeccakHash(const kparams_s *params) NOEXCEPT { sponge_init(sp, params); }
    /** @endcond */
    
public:
    /** Add more data to running hash */
    inline void update(const uint8_t *__restrict__ in, size_t len) { sha3_update(sp,in,len); }

    /** Add more data to running hash, C++ version. */
    inline void update(const Block &s) { sha3_update(sp,s.data(),s.size()); }
    
    /** Add more data, stream version. */
    inline KeccakHash &operator<<(const Block &s) { update(s); return *this; }
    
    /** Same as <<. */
    inline KeccakHash &operator+=(const Block &s) { return *this << s; }
    
    /**
     * @brief Output bytes from the sponge.
     * @todo make this throw exceptions.
     */
    inline void output(Buffer b) { sha3_output(sp,b.data(),b.size()); }
    
    /** @brief Output bytes from the sponge. */
    inline SecureBuffer output(size_t len) {
        SecureBuffer buffer(len);
        sha3_output(sp,buffer.data(),len);
        return buffer;
    }
    
    /** @brief Return the sponge's default output size. */
    inline size_t default_output_size() const NOEXCEPT {
        return sponge_default_output_bytes(sp);
    }
    
    /** Output the default number of bytes. */
    inline SecureBuffer output() {
        return output(default_output_size());
    }
    
    /** Destructor zeroizes state */
    inline ~KeccakHash() NOEXCEPT { sponge_destroy(sp); }
};

/** Fixed-output-length SHA3 */
template<int bits> class SHA3 : public KeccakHash {
private:
    /** Get the parameter template block for this hash */
    static inline const struct kparams_s *get_params();
    
public:
    /** Number of bytes of output */
    static const size_t MAX_OUTPUT_BYTES = bits/8;
    
    /** Initializer */
    inline SHA3() NOEXCEPT : KeccakHash(get_params()) {}

    /** Reset the hash to the empty string */
    inline void reset() NOEXCEPT { sponge_init(sp, get_params()); }

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
    static inline const struct kparams_s *get_params();
public:
    /** Initializer */
    inline SHAKE() NOEXCEPT : KeccakHash(get_params()) {}

    /** Reset the hash to the empty string */
    inline void reset() NOEXCEPT { sponge_init(sp, get_params()); }
    
    /** Hash bytes with this SHAKE instance */
    static inline SecureBuffer hash(const Block &b, size_t outlen) throw(std::bad_alloc) {
        SHAKE s; s += b; return s.output(outlen);
    }
};

/** @cond internal */
template<> inline const struct kparams_s *SHAKE<128>::get_params() { return &SHAKE128_params_s; }
template<> inline const struct kparams_s *SHAKE<256>::get_params() { return &SHAKE256_params_s; }
template<> inline const struct kparams_s *SHA3<224>::get_params() { return &SHA3_224_params_s; }
template<> inline const struct kparams_s *SHA3<256>::get_params() { return &SHA3_256_params_s; }
template<> inline const struct kparams_s *SHA3<384>::get_params() { return &SHA3_384_params_s; }
template<> inline const struct kparams_s *SHA3<512>::get_params() { return &SHA3_512_params_s; }
/** @endcond */

/** @brief An exception for misused protocol, eg encrypt with no key. */
class ProtocolException : public std::exception {
public:
    /** @return "ProtocolException" */
    virtual const char * what() const NOEXCEPT { return "ProtocolException"; }
};

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

/** STROBE protocol framework object */
class Strobe {
private:
    /** The wrapped object */
    keccak_strobe_t sp;
    
public:
    /** Number of bytes in a default authentication size. */
    static const uint16_t DEFAULT_AUTH_SIZE = 16;
    
    /** Am I a server or a client? */
    enum client_or_server { SERVER, CLIENT };
    
    /** Create protocol object. */
    inline Strobe (
        const char *description, /**< Description of this protocol. */
        client_or_server whoami, /**< Am I client or server? */
        const kparams_s &params = STROBE_256 /**< Strength parameters */
    ) NOEXCEPT {
        strobe_init(sp, &params, description, whoami == CLIENT);
        keyed = false;
    }
    
    /** Securely destroy by overwriting state. */
    inline ~Strobe() NOEXCEPT { strobe_destroy(sp); }

    /** Stir in fixed key, from a C++ block. */
    inline void fixed_key (
        const Block &data /**< The key. */
    ) throw(ProtocolException) {
        strobe_fixed_key(sp, data.data(), data.size());
        keyed = true;
    }

    /** Stir in fixed key, from a serializeable object. */
    template<class T> inline void fixed_key (
        const Serializable<T> &data /**< The key. */
    ) throw(ProtocolException) {
        fixed_key(data.serialize());
    }

    /** Stir in DH key, from a C++ block. */
    inline void dh_key (
        const Block &data /**< The key. */
    ) throw(ProtocolException) {
        strobe_dh_key(sp, data.data(), data.size());
        keyed = true;
    }

    /** Stir in DH key, from a serializeable object. */
    template<class T> inline void dh_key (
        const Serializable<T> &data /**< The key. */
    ) throw(ProtocolException) {
        dh_key(data.serialize());
    }

    /** Stir in an explicit nonce. */
    inline void nonce(const Block &data) NOEXCEPT {
        strobe_nonce(sp, data.data(), data.size());
    }

    /** Stir in data we sent as plaintext.  NB This doesn't actually send anything. */
    inline void send_plaintext(const Block &data) NOEXCEPT {
        strobe_plaintext(sp, data.data(), data.size(), true);
    }

    /** Stir in serializeable data we sent as plaintext.  NB This doesn't actually send anything. */
    template<class T> inline void send_plaintext(const Serializable<T> &data) NOEXCEPT {
        send_plaintext(data.serialize());
    }

    /** Stir in data we received as plaintext.  NB This doesn't actually receive anything. */
    inline void recv_plaintext(const Block &data) NOEXCEPT {
        strobe_plaintext(sp, data.data(), data.size(), false);
    }

    /** Stir in associated data. */
    inline void ad(const Block &data) {
        strobe_ad(sp, data.data(), data.size());
    }

    /** Stir in associated serializable data. */
    template<class T> inline void ad(const Serializable<T> &data) NOEXCEPT {
        ad(data.serialize());
    }
    
    /** Encrypt into a buffer, without appending authentication data */
    inline void encrypt_no_auth(Buffer out, const Block &data) throw(LengthException,ProtocolException) {
        if (!keyed) throw ProtocolException();
        if (out.size() != data.size()) throw LengthException();
        strobe_encrypt(sp, out.data(), data.data(), data.size());
    }
    
    /** Encrypt, without appending authentication data */
    inline SecureBuffer encrypt_no_auth(const Block &data) throw(ProtocolException) {
        SecureBuffer out(data.size()); encrypt_no_auth(out, data); return out;
    }
    
    /** Encrypt a serializable object, without appending authentication data */
    template<class T> inline SecureBuffer encrypt_no_auth(const Serializable<T> &data) throw(ProtocolException) {
        return encrypt_no_auth(data.serialize());
    }
    
    /** Decrypt into a buffer, without checking authentication data. */
    inline void decrypt_no_auth(Buffer out, const Block &data) throw(LengthException,ProtocolException) {
        if (!keyed) throw ProtocolException();
        if (out.size() != data.size()) throw LengthException();
        strobe_decrypt(sp, out.data(), data.data(), data.size());
    }
    
    /** Decrypt, without checking authentication data. */
    inline SecureBuffer decrypt_no_auth(const Block &data) throw(ProtocolException) {
        SecureBuffer out(data.size()); decrypt_no_auth(out, data); return out;
    }
    
    /** Produce an authenticator into a buffer. */
    inline void produce_auth(Buffer out, bool even_though_unkeyed = false) throw(LengthException,ProtocolException) {
        if (!keyed && !even_though_unkeyed) throw ProtocolException();
        if (out.size() > STROBE_MAX_AUTH_BYTES) throw LengthException();
        strobe_produce_auth(sp, out.data(), out.size());
    }
    
    /** Produce an authenticator. */
    inline SecureBuffer produce_auth(uint8_t bytes = DEFAULT_AUTH_SIZE) throw(ProtocolException) {
        SecureBuffer out(bytes); produce_auth(out); return out;
    }
    
    /** Encrypt into a buffer and append authentication data */
    inline void encrypt(
        Buffer out, const Block &data, uint8_t auth = DEFAULT_AUTH_SIZE
    ) throw(LengthException,ProtocolException) {
        if (out.size() < data.size() || out.size() != data.size() + auth) throw LengthException();
        encrypt_no_auth(out.slice(0,data.size()), data);
        produce_auth(out.slice(data.size(),auth));
    }
    
    /** Encrypt and append authentication data */
    inline SecureBuffer encrypt (
        const Block &data, uint8_t auth = DEFAULT_AUTH_SIZE
    ) throw(LengthException,ProtocolException,std::bad_alloc ){
        SecureBuffer out(data.size() + auth); encrypt(out, data, auth); return out;
    }
    
    /** Encrypt a serializable object and append authentication data */
    template<class T> inline SecureBuffer encrypt (
        const Serializable<T> &data, uint8_t auth = DEFAULT_AUTH_SIZE
    ) throw(LengthException,ProtocolException,std::bad_alloc ){
        return encrypt(data.serialize(), auth);
    }
    
    /** Decrypt into a buffer and check authentication data */
    inline void decrypt (
        Buffer out, const Block &data, uint8_t bytes = DEFAULT_AUTH_SIZE
    ) throw(LengthException, CryptoException, ProtocolException) {
        if (out.size() > data.size() || out.size() != data.size() - bytes) throw LengthException();
        decrypt_no_auth(out, data.slice(0,out.size()));
        verify_auth(data.slice(out.size(),bytes));
    }
    
    /** Decrypt and check authentication data */
    inline SecureBuffer decrypt (
        const Block &data, uint8_t bytes = DEFAULT_AUTH_SIZE
    ) throw(LengthException,CryptoException,ProtocolException,std::bad_alloc) {
        if (data.size() < bytes) throw LengthException();
        SecureBuffer out(data.size() - bytes); decrypt(out, data, bytes); return out;
    }
    
    /** Check authentication data */
    inline void verify_auth(const Block &auth) throw(LengthException,CryptoException) {
        if (auth.size() == 0 || auth.size() > STROBE_MAX_AUTH_BYTES) throw LengthException();
        if (strobe_verify_auth(sp, auth.data(), auth.size()) != DECAF_SUCCESS) throw CryptoException();
    }
    
    /** Fill pseudorandom data into a buffer */
    inline void prng(Buffer out) NOEXCEPT {
        (void)strobe_prng(sp, out.data(), out.size());
    }
    
    /** Return pseudorandom data */
    inline SecureBuffer prng(size_t bytes) {
        SecureBuffer out(bytes); prng(out); return out;
    }
    
    /** Change specs, perhaps to a faster spec that takes advantage of being keyed.
     * @warning Experimental.
     */
    inline void respec(const kparams_s &params) throw(ProtocolException) {
        if (!keyed) throw(ProtocolException());
        strobe_respec(sp, &params);
    }
    
private:
    bool keyed;
};
  
} /* namespace decaf */

#undef NOEXCEPT
#undef DELETE

#endif /* __SHAKE_HXX__ */
