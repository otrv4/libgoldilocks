/*
 * Example Decaf cyrpto routines, C++ wrapper.
 * @warning These are merely examples, though they ought to be secure.  But real
 * protocols will decide differently on magic numbers, formats, which items to
 * hash, etc.
 * @warning Experimental!  The names, parameter orders etc are likely to change.
 */

#include <decaf/decaf_$(gf_bits).hxx>
#include <decaf/shake.hxx>
#include <decaf/strobe.hxx>

/** @cond internal */
#if __cplusplus >= 201103L
#define NOEXCEPT noexcept
#else
#define NOEXCEPT throw()
#endif
/** @endcond */

namespace decaf {

/** A public key for crypto over some Group */
template <typename Group> class PublicKey;

/** A private key for crypto over some Group */
template <typename Group> class PrivateKey;

/** A public key for crypto over $(name) */
template<> class PublicKey<$(cxx_ns)>
  : public Serializable< PublicKey<$(cxx_ns)> > {
private:
/** @cond internal */
    typedef $(c_ns)_public_key_t Wrapped;
    Wrapped wrapped;
    template<class Group> friend class PrivateKey;
/** @endcond */
public:
    /** Underlying group */
    typedef $(cxx_ns) Group;
    
    /** Signature size. */
    static const size_t SIG_BYTES = sizeof($(c_ns)_signature_t);
    
    /** Serialization size. */
    static const size_t SER_BYTES = sizeof(Wrapped);
    
    /** Read a private key from a string*/
    inline explicit PublicKey(const FixedBlock<SER_BYTES> &b) NOEXCEPT {
        memcpy(wrapped,b.data(),sizeof(wrapped));
    }
    
    /** Read a private key from a string*/
    inline explicit PublicKey(const PrivateKey<$(cxx_ns)> &b) NOEXCEPT;
    
    /** Create but don't initialize */
    inline explicit PublicKey(const NOINIT&) NOEXCEPT { }
    
    /** Serialize into a buffer. */
    inline void serialize_into(unsigned char *x) const NOEXCEPT {
        memcpy(x,wrapped,sizeof(wrapped));
    }
    
    /** Serialization size. */
    inline size_t serSize() const NOEXCEPT { return SER_BYTES; }
    
    /** Verify a message */
    inline void verify(
        const Block &message,
        const FixedBlock<SIG_BYTES> &sig
    ) const throw(CryptoException) {
        if (DECAF_SUCCESS != $(c_ns)_verify(sig.data(),wrapped,message.data(),message.size())) {
            throw(CryptoException());
        }
    }
    
    /** Verify a message */
    inline void verify(
        Strobe &context,
        const FixedBlock<SIG_BYTES> &sig
    ) const throw(CryptoException) {
        if (DECAF_SUCCESS != $(c_ns)_verify_strobe(context.wrapped,sig.data(),wrapped)) {
            throw(CryptoException());
        }
    }
};

/** A private key for crypto over $(name) */
template<> class PrivateKey<$(cxx_ns)>
  : public Serializable< PrivateKey<$(cxx_ns)> > {
private:
/** @cond internal */
    typedef $(c_ns)_private_key_t Wrapped;
    Wrapped wrapped;
    template<class Group> friend class PublicKey;
/** @endcond */
public:
    /** Underlying group */
    typedef $(cxx_ns) Group;
    
    /** Signature size. */
    static const size_t SIG_BYTES = sizeof($(c_ns)_signature_t);
    
    /** Serialization size. */
    static const size_t SER_BYTES = sizeof(Wrapped);
    
    /** Compressed size. */
    static const size_t SYM_BYTES = $(C_NS)_SYMMETRIC_KEY_BYTES;
    
    /** Create but don't initialize */
    inline explicit PrivateKey(const NOINIT&) NOEXCEPT { }
    
    /** Read a private key from a string*/
    inline explicit PrivateKey(const FixedBlock<SER_BYTES> &b) NOEXCEPT {
        memcpy(wrapped,b.data(),sizeof(wrapped));
    }
    
    /** Read a private key from a string*/
    inline explicit PrivateKey(const FixedBlock<SYM_BYTES> &b) NOEXCEPT {
        $(c_ns)_derive_private_key(wrapped, b.data());
    }
    
    /** Create at random */
    inline explicit PrivateKey(Rng &r) NOEXCEPT {
        FixedArrayBuffer<SYM_BYTES> tmp(r);
        $(c_ns)_derive_private_key(wrapped, tmp.data());
    }
    
    /** Secure destructor */
    inline ~PrivateKey() NOEXCEPT {
        $(c_ns)_destroy_private_key(wrapped);
    }
    
    /** Serialization size. */
    inline size_t serSize() const NOEXCEPT { return SER_BYTES; }
    
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
    inline PublicKey<$(cxx_ns)> pub() const NOEXCEPT {
        PublicKey<$(cxx_ns)> ret(*this); return ret;
    }
    
    /** Derive a shared secret */
    inline SecureBuffer sharedSecret(
        const PublicKey<$(cxx_ns)> &pub,
        size_t bytes,
        bool me_first
    ) const throw(CryptoException,std::bad_alloc) {
        SecureBuffer ret(bytes);
        if (DECAF_SUCCESS != $(c_ns)_shared_secret(ret.data(),bytes,wrapped,pub.wrapped,me_first)) {
            throw(CryptoException());
        }
        return ret;
    }
    
    /** Derive a shared secret */
    inline decaf_error_t __attribute__((warn_unused_result))
    sharedSecretNoexcept(
        Buffer ret,
        const PublicKey<$(cxx_ns)> &pub,
        bool me_first
    ) const NOEXCEPT {
        return $(c_ns)_shared_secret(ret.data(),ret.size(),wrapped,pub.wrapped,me_first);
    }

    /** Sign a message. */ 
    inline SecureBuffer sign(const Block &message) const {
        SecureBuffer sig(SIG_BYTES);
        $(c_ns)_sign(sig.data(), wrapped, message.data(), message.size());
        return sig;
    }

    /** Sign a message. */ 
    inline SecureBuffer verify(Strobe &context) const {
        SecureBuffer sig(SIG_BYTES);
        $(c_ns)_sign_strobe(context.wrapped, sig.data(), wrapped);
        return sig;
    }
};

/** @cond internal */
PublicKey<$(cxx_ns)>::PublicKey(const PrivateKey<$(cxx_ns)> &b) NOEXCEPT {
    $(c_ns)_private_to_public(wrapped,b.wrapped);
}
/** @endcond */

#undef NOEXCEPT
} /* namespace decaf */