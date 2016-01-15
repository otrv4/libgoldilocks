from gen_file import gen_file

crypto_hxx = gen_file(
    public = True,
    per = "curve",
    name = "decaf/crypto_%(shortname)s.hxx",
    doc = """
        Example Decaf cyrpto routines, C++ wrapper.
        @warning These are merely examples, though they ought to be secure.  But real
        protocols will decide differently on magic numbers, formats, which items to
        hash, etc.
        @warning Experimental!  The names, parameter orders etc are likely to change.
    """, code = """
#include <decaf.hxx>
#include <decaf/shake.hxx>

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

/** A public key for crypto over %(name)s */
template<> class PublicKey<%(cxx_ns)s>
  : public Serializable< PublicKey<%(cxx_ns)s> > {
private:
/** @cond internal */
    typedef %(c_ns)s_public_key_t Wrapped;
    Wrapped wrapped;
    template<class Group> friend class PrivateKey;
/** @endcond */
public:
    /** Underlying group */
    typedef %(cxx_ns)s Group;
    
    /** Signature size. */
    static const size_t SIG_BYTES = sizeof(%(c_ns)s_signature_t);
    
    /** Serialization size. */
    static const size_t SER_BYTES = sizeof(Wrapped);
    
    /* TODO: convenience types like signature? */
    
    /** Read a private key from a string*/
    inline explicit PublicKey(const FixedBlock<SER_BYTES> &b) NOEXCEPT {
        memcpy(wrapped,b.data(),sizeof(wrapped));
    }
    
    /** Read a private key from a string*/
    inline explicit PublicKey(const PrivateKey<%(cxx_ns)s> &b) NOEXCEPT;
    
    /** Create but don't initialize */
    inline explicit PublicKey(const NOINIT&) NOEXCEPT { }
    
    /** Serialize into a buffer. */
    inline void serializeInto(unsigned char *x) const NOEXCEPT {
        memcpy(x,wrapped,sizeof(wrapped));
    }
    
    /** Serialization size. */
    inline size_t serSize() const NOEXCEPT { return SER_BYTES; }
    
    /* TODO: verify_strobe */
    
    /** Verify a message */
    inline void verify(
        const Block &message,
        const FixedBlock<SIG_BYTES> &sig
    ) const throw(CryptoException) {
        if (DECAF_SUCCESS != %(c_ns)s_verify(sig.data(),wrapped,message.data(),message.size())) {
            throw(CryptoException());
        }
    }
};

/** A private key for crypto over %(name)s */
template<> class PrivateKey<%(cxx_ns)s>
  : public Serializable< PrivateKey<%(cxx_ns)s> > {
private:
/** @cond internal */
    typedef %(c_ns)s_private_key_t Wrapped;
    Wrapped wrapped;
    template<class Group> friend class PublicKey;
/** @endcond */
public:
    /** Underlying group */
    typedef %(cxx_ns)s Group;
    
    /** Signature size. */
    static const size_t SIG_BYTES = sizeof(%(c_ns)s_signature_t);
    
    /** Serialization size. */
    static const size_t SER_BYTES = sizeof(Wrapped);
    
    /** Compressed size. */
    static const size_t SYM_BYTES = %(C_NS)s_SYMMETRIC_KEY_BYTES;
    
    /** Create but don't initialize */
    inline explicit PrivateKey(const NOINIT&) NOEXCEPT { }
    
    /** Read a private key from a string*/
    inline explicit PrivateKey(const FixedBlock<SER_BYTES> &b) NOEXCEPT {
        memcpy(wrapped,b.data(),sizeof(wrapped));
    }
    
    /** Read a private key from a string*/
    inline explicit PrivateKey(const FixedBlock<SYM_BYTES> &b) NOEXCEPT {
        %(c_ns)s_derive_private_key(wrapped, b.data());
    }
    
    /** Create at random */
    inline explicit PrivateKey(Rng &r) NOEXCEPT {
        FixedArrayBuffer<SYM_BYTES> tmp(r);
        %(c_ns)s_derive_private_key(wrapped, tmp.data());
    }
    
    /** Secure destructor */
    inline ~PrivateKey() NOEXCEPT {
        %(c_ns)s_destroy_private_key(wrapped);
    }
    
    /** Serialization size. */
    inline size_t serSize() const NOEXCEPT { return SER_BYTES; }
    
    /** Serialize into a buffer. */
    inline void serializeInto(unsigned char *x) const NOEXCEPT {
        memcpy(x,wrapped,sizeof(wrapped));
    }
    
    /** Compressed serialize. */
    inline SecureBuffer compress() const throw(std::bad_alloc) {
        SecureBuffer ret(sizeof(wrapped->sym));
        memcpy(ret.data(),wrapped->sym,sizeof(wrapped->sym));
        return ret;
    }
    
    /** Get the public key */
    inline PublicKey<%(cxx_ns)s> pub() const NOEXCEPT {
        PublicKey<%(cxx_ns)s> ret(*this); return ret;
    }
    
    /** Derive a shared secret */
    inline SecureBuffer sharedSecret(
        const PublicKey<%(cxx_ns)s> &pub,
        size_t bytes,
        bool me_first
    ) const throw(CryptoException,std::bad_alloc) {
        SecureBuffer ret(bytes);
        if (DECAF_SUCCESS != %(c_ns)s_shared_secret(ret.data(),bytes,wrapped,pub.wrapped,me_first)) {
            throw(CryptoException());
        }
        return ret;
    }

    /** Sign a message. */ 
    inline SecureBuffer sign(const Block &message) const {
        SecureBuffer sig(SIG_BYTES);
        %(c_ns)s_sign(sig.data(), wrapped, message.data(), message.size());
        return sig;
    }
};

/** @cond internal */
PublicKey<%(cxx_ns)s>::PublicKey(const PrivateKey<%(cxx_ns)s> &b) NOEXCEPT {
    %(c_ns)s_private_to_public(wrapped,b.wrapped);
}
/** @endcond */

#undef NOEXCEPT
} /* namespace decaf */
""")