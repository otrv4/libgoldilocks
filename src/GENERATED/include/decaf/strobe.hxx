/**
 * @file decaf/strobe.hxx
 * @copyright
 *   Based on CC0 code by David Leon Gil, 2015 \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief STROBE instances, C++ wrapper.
 * @warning This protocol framework is entirely experimental, and shouldn't be
 * relied on for anything serious yet.
 */

#ifndef __DECAF_STROBE_HXX__
#define __DECAF_STROBE_HXX__

#include <decaf/strobe.h>

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

/** @brief An exception for misused protocol, eg encrypt with no key. */
class ProtocolException : public std::exception {
public:
    /** @return "ProtocolException" */
    virtual const char * what() const NOEXCEPT { return "ProtocolException"; }
};

/** STROBE protocol framework object */
class Strobe {
public:
    /** The wrapped object */
    keccak_strobe_t wrapped;
    
    /** Number of bytes in a default authentication size. */
    static const uint16_t DEFAULT_AUTH_SIZE = 16;
    
    /** Am I a server or a client? */
    enum client_or_server { SERVER, CLIENT };
    
    /** Create protocol object. */
    inline Strobe (
        const char *description, /**< Description of this protocol. */
        client_or_server whoami, /**< Am I client or server? */
        const decaf_kparams_s &params = STROBE_256 /**< Strength parameters */
    ) NOEXCEPT {
        strobe_init(wrapped, &params, description, whoami == CLIENT);
        keyed = false;
    }
    
    /** Securely destroy by overwriting state. */
    inline ~Strobe() NOEXCEPT { strobe_destroy(wrapped); }

    /** Stir in fixed key, from a C++ block. */
    inline void fixed_key (
        const Block &data /**< The key. */
    ) throw(ProtocolException) {
        strobe_fixed_key(wrapped, data.data(), data.size());
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
        strobe_dh_key(wrapped, data.data(), data.size());
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
        strobe_nonce(wrapped, data.data(), data.size());
    }

    /** Stir in data we sent as plaintext.  NB This doesn't actually send anything. */
    inline void send_plaintext(const Block &data) NOEXCEPT {
        strobe_plaintext(wrapped, data.data(), data.size(), true);
    }

    /** Stir in serializeable data we sent as plaintext.  NB This doesn't actually send anything. */
    template<class T> inline void send_plaintext(const Serializable<T> &data) NOEXCEPT {
        send_plaintext(data.serialize());
    }

    /** Stir in data we received as plaintext.  NB This doesn't actually receive anything. */
    inline void recv_plaintext(const Block &data) NOEXCEPT {
        strobe_plaintext(wrapped, data.data(), data.size(), false);
    }

    /** Stir in associated data. */
    inline void ad(const Block &data) {
        strobe_ad(wrapped, data.data(), data.size());
    }

    /** Stir in associated serializable data. */
    template<class T> inline void ad(const Serializable<T> &data) NOEXCEPT {
        ad(data.serialize());
    }
    
    /** Encrypt into a buffer, without appending authentication data */
    inline void encrypt_no_auth(Buffer out, const Block &data) throw(LengthException,ProtocolException) {
        if (!keyed) throw ProtocolException();
        if (out.size() != data.size()) throw LengthException();
        strobe_encrypt(wrapped, out.data(), data.data(), data.size());
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
        strobe_decrypt(wrapped, out.data(), data.data(), data.size());
    }
    
    /** Decrypt, without checking authentication data. */
    inline SecureBuffer decrypt_no_auth(const Block &data) throw(ProtocolException) {
        SecureBuffer out(data.size()); decrypt_no_auth(out, data); return out;
    }
    
    /** Produce an authenticator into a buffer. */
    inline void produce_auth(Buffer out, bool even_though_unkeyed = false) throw(LengthException,ProtocolException) {
        if (!keyed && !even_though_unkeyed) throw ProtocolException();
        if (out.size() > STROBE_MAX_AUTH_BYTES) throw LengthException();
        strobe_produce_auth(wrapped, out.data(), out.size());
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
        if (strobe_verify_auth(wrapped, auth.data(), auth.size()) != DECAF_SUCCESS) throw CryptoException();
    }
    
    /** Fill pseudorandom data into a buffer */
    inline void prng(Buffer out) NOEXCEPT {
        (void)strobe_prng(wrapped, out.data(), out.size());
    }
    
    /** Return pseudorandom data */
    inline SecureBuffer prng(size_t bytes) {
        SecureBuffer out(bytes); prng(out); return out;
    }
    
    /** Change specs, perhaps to a faster spec that takes advantage of being keyed.
     * @warning Experimental.
     */
    inline void respec(const decaf_kparams_s &params) throw(ProtocolException) {
        if (!keyed) throw(ProtocolException());
        strobe_respec(wrapped, &params);
    }
    
private:
    bool keyed;
};
  
} /* namespace decaf */

#undef NOEXCEPT
#undef DELETE

#endif /* __DECAF_STROBE_HXX__ */
