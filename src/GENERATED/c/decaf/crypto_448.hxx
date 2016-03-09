/**
 * @file src/GENERATED/c/decaf/crypto_448.hxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 *
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */

#ifndef __SRC_GENERATED_C_DECAF_CRYPTO_448_HXX__
#define __SRC_GENERATED_C_DECAF_CRYPTO_448_HXX__ 1
/*
 * Example Decaf cyrpto routines, C++ wrapper.
 * @warning These are merely examples, though they ought to be secure.  But real
 * protocols will decide differently on magic numbers, formats, which items to
 * hash, etc.
 * @warning Experimental!  The names, parameter orders etc are likely to change.
 */

#include <decaf/decaf_448.hxx>
#include <decaf/shake.hxx>
#include <decaf/strobe.hxx>

/** @cond internal */
#if __cplusplus >= 201103L
#define NOEXCEPT noexcept
#else
#define NOEXCEPT throw()
#endif
/** @endcond */

namespace decaf { namespace TOY {

/** A public key for crypto over some Group */
template <typename Group> class PublicKey;

/** A private key for crypto over some Group */
template <typename Group> class PrivateKey;

/** A public key for crypto over Ed448-Goldilocks */
template<> class PublicKey<Ed448Goldilocks>
  : public Serializable< PublicKey<Ed448Goldilocks> > {
private:
/** @cond internal */
    typedef decaf_448_TOY_public_key_t Wrapped;
    Wrapped wrapped;
    template<class Group> friend class PrivateKey;
/** @endcond */
public:
    /** Underlying group */
    typedef Ed448Goldilocks Group;
    
    /** Signature size. */
    static const size_t SIG_BYTES = sizeof(decaf_448_TOY_signature_t);
    
    /** Serialization size. */
    static const size_t SER_BYTES = sizeof(Wrapped);
    
    /** Read a private key from a string*/
    inline explicit PublicKey(const FixedBlock<SER_BYTES> &b) NOEXCEPT {
        memcpy(wrapped,b.data(),sizeof(wrapped));
    }
    
    /** Read a private key from a string*/
    inline explicit PublicKey(const PrivateKey<Ed448Goldilocks> &b) NOEXCEPT;
    
    /** Create but don't initialize */
    inline explicit PublicKey(const NOINIT&) NOEXCEPT { }
    
    /** Serialize into a buffer. */
    inline void serialize_into(unsigned char *x) const NOEXCEPT {
        memcpy(x,wrapped,sizeof(wrapped));
    }
    
    /** Serialization size. */
    inline size_t ser_size() const NOEXCEPT { return SER_BYTES; }
    
    /** Verify a message */
    inline void verify(
        const Block &message,
        const FixedBlock<SIG_BYTES> &sig
    ) const throw(CryptoException) {
        if (DECAF_SUCCESS != decaf_448_TOY_verify(sig.data(),wrapped,message.data(),message.size())) {
            throw(CryptoException());
        }
    }
    
    /** Verify a message */
    inline void verify(
        Strobe &context,
        const FixedBlock<SIG_BYTES> &sig
    ) const throw(CryptoException) {
        if (DECAF_SUCCESS != decaf_448_TOY_verify_strobe(context.wrapped,sig.data(),wrapped)) {
            throw(CryptoException());
        }
    }
};

/** A private key for crypto over Ed448-Goldilocks */
template<> class PrivateKey<Ed448Goldilocks>
  : public Serializable< PrivateKey<Ed448Goldilocks> > {
private:
/** @cond internal */
    typedef decaf_448_TOY_private_key_t Wrapped;
    Wrapped wrapped;
    template<class Group> friend class PublicKey;
/** @endcond */
public:
    /** Underlying group */
    typedef Ed448Goldilocks Group;
    
    /** Signature size. */
    static const size_t SIG_BYTES = sizeof(decaf_448_TOY_signature_t);
    
    /** Serialization size. */
    static const size_t SER_BYTES = sizeof(Wrapped);
    
    /** Compressed size. */
    static const size_t SYM_BYTES = DECAF_448_SYMMETRIC_KEY_BYTES;
    
    /** Create but don't initialize */
    inline explicit PrivateKey(const NOINIT&) NOEXCEPT { }
    
    /** Read a private key from a string*/
    inline explicit PrivateKey(const FixedBlock<SER_BYTES> &b) NOEXCEPT {
        memcpy(wrapped,b.data(),sizeof(wrapped));
    }
    
    /** Read a private key from a string*/
    inline explicit PrivateKey(const FixedBlock<SYM_BYTES> &b) NOEXCEPT {
        decaf_448_TOY_derive_private_key(wrapped, b.data());
    }
    
    /** Create at random */
    inline explicit PrivateKey(Rng &r) NOEXCEPT {
        FixedArrayBuffer<SYM_BYTES> tmp(r);
        decaf_448_TOY_derive_private_key(wrapped, tmp.data());
    }
    
    /** Secure destructor */
    inline ~PrivateKey() NOEXCEPT {
        decaf_448_TOY_destroy_private_key(wrapped);
    }
    
    /** Serialization size. */
    inline size_t ser_size() const NOEXCEPT { return SER_BYTES; }
    
    /** Serialize into a buffer. */
    inline void serialize_into(unsigned char *x) const NOEXCEPT {
        memcpy(x,wrapped,sizeof(wrapped));
    }
    
    /** Compressed serialize. */
    inline SecureBuffer compress() const throw(std::bad_alloc) {
        SecureBuffer ret(sizeof(wrapped->sym));
        memcpy(ret.data(),wrapped->sym,sizeof(wrapped->sym));
        return ret;
    }
    
    /** Get the public key */
    inline PublicKey<Ed448Goldilocks> pub() const NOEXCEPT {
        PublicKey<Ed448Goldilocks> ret(*this); return ret;
    }
    
    /** Derive a shared secret */
    inline SecureBuffer shared_secret(
        const PublicKey<Ed448Goldilocks> &pub,
        size_t bytes,
        bool me_first
    ) const throw(CryptoException,std::bad_alloc) {
        SecureBuffer ret(bytes);
        if (DECAF_SUCCESS != decaf_448_TOY_shared_secret(ret.data(),bytes,wrapped,pub.wrapped,me_first)) {
            throw(CryptoException());
        }
        return ret;
    }
    
    /** Derive a shared secret */
    inline decaf_error_t __attribute__((warn_unused_result))
    shared_secret_noexcept(
        Buffer ret,
        const PublicKey<Ed448Goldilocks> &pub,
        bool me_first
    ) const NOEXCEPT {
        return decaf_448_TOY_shared_secret(ret.data(),ret.size(),wrapped,pub.wrapped,me_first);
    }

    /** Sign a message. */ 
    inline SecureBuffer sign(const Block &message) const {
        SecureBuffer sig(SIG_BYTES);
        decaf_448_TOY_sign(sig.data(), wrapped, message.data(), message.size());
        return sig;
    }

    /** Sign a message. */ 
    inline SecureBuffer verify(Strobe &context) const {
        SecureBuffer sig(SIG_BYTES);
        decaf_448_TOY_sign_strobe(context.wrapped, sig.data(), wrapped);
        return sig;
    }
};

/** @cond internal */
PublicKey<Ed448Goldilocks>::PublicKey(const PrivateKey<Ed448Goldilocks> &b) NOEXCEPT {
    decaf_448_TOY_private_to_public(wrapped,b.wrapped);
}
/** @endcond */

#undef NOEXCEPT
}} /* namespace decaf::TOY */
#endif /* __SRC_GENERATED_C_DECAF_CRYPTO_448_HXX__ */
