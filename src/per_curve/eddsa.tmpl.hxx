
/*
 * Example Decaf cyrpto routines, C++ wrapper.
 * @warning These are merely examples, though they ought to be secure.  But real
 * protocols will decide differently on magic numbers, formats, which items to
 * hash, etc.
 * @warning Experimental!  The names, parameter orders etc are likely to change.
 */

#include <decaf/eddsa.hxx>
#include <decaf/decaf_$(gf_bits).hxx>
#include <decaf/ed$(gf_bits).h>

#include <decaf/shake.hxx>
#include <decaf/sha512.hxx>

/** @cond internal */
#if __cplusplus >= 201103L
#define NOEXCEPT noexcept
#else
#define NOEXCEPT throw()
#endif
/** @endcond */

namespace decaf {

/** A public key for crypto over some Group */
template <typename Group> struct EdDSA;

/** A public key for crypto over $(name) */
template<> struct EdDSA<$(cxx_ns)> {

/** @cond internal */
template<class CRTP, Prehashed> class Signing;
template<class CRTP, Prehashed> class Verification;
$("""
class PublicKeyBase;
class PrivateKeyBase;
typedef class PrivateKeyBase PrivateKey, PrivateKeyPure, PrivateKeyPh;
typedef class PublicKeyBase PublicKey, PublicKeyPure, PublicKeyPh;
  """ if eddsa_supports_contexts else """
template<Prehashed=PURE> class PublicKeyBase;
template<Prehashed=PURE> class PrivateKeyBase;
typedef class PublicKeyBase<PURE> PublicKey, PublicKeyPure;
typedef class PublicKeyBase<PREHASHED> PublicKeyPh;
typedef class PrivateKeyBase<PURE> PrivateKey, PrivateKeyPure;
typedef class PrivateKeyBase<PREHASHED> PrivateKeyPh;
""")
/** @endcond */

/** Prehash context for EdDSA. */
class Prehash : public $(re.sub(r"SHAKE(\d+)",r"SHAKE<\1>", eddsa_hash.upper())) {
public:
    /** Do we support contexts for signatures?  If not, they must always be NULL */
    static const bool SUPPORTS_CONTEXTS = DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS;
    
private:
    typedef $(re.sub(r"SHAKE(\d+)",r"SHAKE<\1>", eddsa_hash.upper())) Super;
    SecureBuffer context_;
    template<class T, Prehashed Ph> friend class Signing;
    template<class T, Prehashed Ph> friend class Verification;
    
    void init() throw(LengthException) {
        Super::reset();
        
        if (context_.size() > 255
            || (context_.size() != 0 && !SUPPORTS_CONTEXTS)
        ) {
            throw LengthException();
        }
        
        if (SUPPORTS_CONTEXTS) {
            uint8_t dom[2] = {2, (uint8_t)context_.size() };
            update(dom,2);
            update(context_);
        }
    }
    
public:
    /** Number of output bytes in prehash */
    static const size_t OUTPUT_BYTES = Super::DEFAULT_OUTPUT_BYTES;
    
    /** Create the prehash */
    Prehash(Block context = Block(NULL,0)) throw(LengthException) {
        context_ = context;
        init();
    }

    /** Reset this hash */
    void reset() NOEXCEPT { init(); }
    
    /** Output from this hash */
    SecureBuffer final() throw(std::bad_alloc) {
        SecureBuffer ret = Super::final(OUTPUT_BYTES);
        reset();
        return ret;
    }
    
    /** Output from this hash */
    void final(Buffer &b) throw(LengthException) {
        if (b.size() != OUTPUT_BYTES) throw LengthException();
        Super::final(b);
        reset();
    }
};

template<class CRTP, Prehashed ph> class Signing;

template<class CRTP> class Signing<CRTP,PREHASHED> {
public:
    /* Sign a prehash context, and reset the context */
    inline SecureBuffer sign_prehashed ( Prehash &ph ) const /*throw(std::bad_alloc)*/ {
        SecureBuffer out(CRTP::SIG_BYTES);
        FixedArrayBuffer<Prehash::OUTPUT_BYTES> tmp;
        ph.final(tmp);
        decaf_ed$(gf_shortname)_sign (
            out.data(),
            ((const CRTP*)this)->priv_.data(),
            ((const CRTP*)this)->pub_.data(),
            tmp.data(),
            tmp.size(),
            1
#if DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS
            , ph.context_.data(),
            ph.context_.size()
#endif
        );
        return out;
    }
    
    /* Sign a message using the prehasher */
    inline SecureBuffer sign_with_prehash (
        const Block &message,
        const Block &context = Block(NULL,0)
    ) const /*throw(LengthException,CryptoException)*/ {
        Prehash ph(context);
        ph += message;
        return sign_prehashed(ph);
    }
};

template<class CRTP> class Signing<CRTP,PURE>  {
public:
    /**
     * Sign a message.
     * @param [in] message The message to be signed.
     * @param [in] context A context for the signature; must be at most 255 bytes;
     * must be absent if SUPPORTS_CONTEXTS == false.
     *
     * @warning It is generally unsafe to use Ed25519 with both prehashed and non-prehashed messages.
     */
    inline SecureBuffer sign (
        const Block &message,
        const Block &context = Block(NULL,0)
    ) const /* TODO: this exn spec tickles a Clang bug?
             * throw(LengthException, std::bad_alloc)
             */ {
        if (context.size() > 255
            || (context.size() != 0 && !CRTP::SUPPORTS_CONTEXTS)
        ) {
            throw LengthException();
        }
        
        SecureBuffer out(CRTP::SIG_BYTES);
        decaf_ed$(gf_shortname)_sign (
            out.data(),
            ((const CRTP*)this)->priv_.data(),
            ((const CRTP*)this)->pub_.data(),
            message.data(),
            message.size(),
            0
#if DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS
            , context.data(),
            context.size()
#endif
        );
        return out;
    }
};

$("""
class PrivateKeyBase
    : public Serializable<PrivateKeyBase>
    , public Signing<PrivateKeyBase,PURE>
    , public Signing<PrivateKeyBase,PREHASHED> {
public:
    typedef class PublicKeyBase MyPublicKey;
private:
/** @cond internal */
    friend class PublicKeyBase;
    friend class Signing<PrivateKey,PURE>;
    friend class Signing<PrivateKey,PREHASHED>;
/** @endcond */
""" if eddsa_supports_contexts else """
template<Prehashed ph> class PrivateKeyBase
    : public Serializable<PrivateKeyBase<ph> >
    , public Signing<PrivateKeyBase<ph>,ph> {
public:
    typedef class PublicKeyBase<ph> MyPublicKey;
private:
/** @cond internal */
    friend class PublicKeyBase<ph>;
    friend class Signing<PrivateKeyBase<ph>, ph>;
/** @endcond */
""")
    
    /** The pre-expansion form of the signing key. */
    FixedArrayBuffer<DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES> priv_;
    
    /** The post-expansion public key. */
    FixedArrayBuffer<DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES> pub_;
    
public:
    /** Underlying group */
    typedef $(cxx_ns) Group;
    
    /** Signature size. */
    static const size_t SIG_BYTES = DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES;
    
    /** Serialization size. */
    static const size_t SER_BYTES = DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES;
    
    /** Do we support contexts for signatures?  If not, they must always be NULL */
    static const bool SUPPORTS_CONTEXTS = DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS;
    
    
    /** Create but don't initialize */
    inline explicit PrivateKeyBase(const NOINIT&) NOEXCEPT : priv_((NOINIT())), pub_((NOINIT())) { }
    
    /** Read a private key from a string */
    inline explicit PrivateKeyBase(const FixedBlock<SER_BYTES> &b) NOEXCEPT { *this = b; }
    
    /** Copy constructor */
    inline PrivateKeyBase(const PrivateKey &k) NOEXCEPT { *this = k; }
    
    /** Create at random */
    inline explicit PrivateKeyBase(Rng &r) NOEXCEPT : priv_(r) {
        decaf_ed$(gf_shortname)_derive_public_key(pub_.data(), priv_.data());
    }
    
    /** Assignment from string */
    inline PrivateKeyBase &operator=(const FixedBlock<SER_BYTES> &b) NOEXCEPT {
        memcpy(priv_.data(),b.data(),b.size());
        decaf_ed$(gf_shortname)_derive_public_key(pub_.data(), priv_.data());
        return *this;
    }
    
    /** Copy assignment */
    inline PrivateKeyBase &operator=(const PrivateKey &k) NOEXCEPT {
        memcpy(priv_.data(),k.priv_.data(), priv_.size());
        memcpy(pub_.data(),k.pub_.data(), pub_.size());
        return *this;
    }
    
    /** Serialization size. */
    inline size_t ser_size() const NOEXCEPT { return SER_BYTES; }
    
    /** Serialize into a buffer. */
    inline void serialize_into(unsigned char *x) const NOEXCEPT {
        memcpy(x,priv_.data(), priv_.size());
    }
    
    /** Return the corresponding public key */
    inline MyPublicKey pub() const NOEXCEPT {
        MyPublicKey pub(*this);
        return pub;
    }
}; /* class PrivateKey */



template<class CRTP> class Verification<CRTP,PURE> {
public:
    /** Verify a signature, returning DECAF_FAILURE if verification fails */
    inline decaf_error_t WARN_UNUSED verify_noexcept (
        const FixedBlock<DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES> &sig,
        const Block &message,
        const Block &context = Block(NULL,0)
    ) const /*NOEXCEPT*/ {
        if (context.size() > 255
            || (context.size() != 0 && !CRTP::SUPPORTS_CONTEXTS)
        ) {
            return DECAF_FAILURE;
        }
        
        return decaf_ed$(gf_shortname)_verify (
            sig.data(),
            ((const CRTP*)this)->pub_.data(),
            message.data(),
            message.size(),
            0
#if DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS
            , context.data(),
            context.size()
#endif
        );
    }
    
    /** Verify a signature, throwing an exception if verification fails
     * @param [in] sig The signature.
     * @param [in] message The signed message.
     * @param [in] context A context for the signature; must be at most 255 bytes;
     * must be absent if SUPPORTS_CONTEXTS == false.
     *
     * @warning It is generally unsafe to use Ed25519 with both prehashed and non-prehashed messages.
     */
    inline void verify (
        const FixedBlock<DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES> &sig,
        const Block &message,
        const Block &context = Block(NULL,0)
    ) const /*throw(LengthException,CryptoException)*/ {
        if (context.size() > 255
            || (context.size() != 0 && !CRTP::SUPPORTS_CONTEXTS)
        ) {
            throw LengthException();
        }
        
        if (DECAF_SUCCESS != verify_noexcept( sig, message, context )) {
            throw CryptoException();
        }
    }
};


template<class CRTP> class Verification<CRTP,PREHASHED> {
public:
    /* Verify a prehash context, and reset the context */
    inline decaf_error_t WARN_UNUSED verify_prehashed_noexcept (
        const FixedBlock<DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES> &sig,
        Prehash &ph
    ) const /*NOEXCEPT*/ {
        FixedArrayBuffer<Prehash::OUTPUT_BYTES> m;
        ph.final(m);
        return decaf_ed$(gf_shortname)_verify (
            sig.data(),
            ((const CRTP*)this)->pub_.data(),
            m.data(),
            m.size(),
            1
#if DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS
            , ph.context_.data(),
            ph.context_.size()
#endif
        );
    }
    
    /* Verify a prehash context, and reset the context */
    inline void verify_prehashed (
        const FixedBlock<DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES> &sig,
        Prehash &ph
    ) const /*throw(CryptoException)*/ {
        FixedArrayBuffer<Prehash::OUTPUT_BYTES> m;
        ph.final(m);
        if (DECAF_SUCCESS != decaf_ed$(gf_shortname)_verify (
            sig.data(),
            ((const CRTP*)this)->pub_.data(),
            m.data(),
            m.size(),
            1
#if DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS
            , ph.context_.data(),
            ph.context_.size()
#endif
        )) {
            throw CryptoException();
        }
    }
    
    /* Verify a message using the prehasher */
    inline void verify_with_prehash (
        const FixedBlock<DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES> &sig,
        const Block &message,
        const Block &context = Block(NULL,0)
    ) const /*throw(LengthException,CryptoException)*/ {
        Prehash ph(context);
        ph += message;
        verify_prehashed(sig,ph);
    }
};


$("""
class PublicKeyBase
    : public Serializable<PublicKeyBase>
    , public Verification<PublicKeyBase,PURE>
    , public Verification<PublicKeyBase,PREHASHED> {
public:
    typedef class PrivateKeyBase MyPrivateKey;
    
private:
/** @cond internal */
    friend class PrivateKeyBase;
    friend class Verification<PublicKey,PURE>;
    friend class Verification<PublicKey,PREHASHED>;
/** @endcond */
""" if eddsa_supports_contexts else """
template<Prehashed ph> class PublicKeyBase
    : public Serializable<PublicKeyBase<ph> >
    , public Verification<PublicKeyBase<ph>,ph> {
public:
    typedef class PrivateKeyBase<ph> MyPrivateKey;
    
private:
/** @cond internal */
    friend class PrivateKeyBase<ph>;
    friend class Verification<PublicKeyBase<ph>, ph>;
/** @endcond */
""")

private:
    /** The pre-expansion form of the signature */
    FixedArrayBuffer<DECAF_EDDSA_$(gf_shortname)_PUBLIC_BYTES> pub_;
    
public:
    /* PERF FUTURE: Pre-cached decoding? Precomputed table?? */
  
    /** Underlying group */
    typedef $(cxx_ns) Group;
    
    /** Signature size. */
    static const size_t SIG_BYTES = DECAF_EDDSA_$(gf_shortname)_SIGNATURE_BYTES;
    
    /** Serialization size. */
    static const size_t SER_BYTES = DECAF_EDDSA_$(gf_shortname)_PRIVATE_BYTES;
    
    /** Do we support contexts for signatures?  If not, they must always be NULL */
    static const bool SUPPORTS_CONTEXTS = DECAF_EDDSA_$(gf_shortname)_SUPPORTS_CONTEXTS;
    
    
    /** Create but don't initialize */
    inline explicit PublicKeyBase(const NOINIT&) NOEXCEPT : pub_((NOINIT())) { }
    
    /** Read a private key from a string */
    inline explicit PublicKeyBase(const FixedBlock<SER_BYTES> &b) NOEXCEPT { *this = b; }
    
    /** Copy constructor */
    inline PublicKeyBase(const PublicKeyBase &k) NOEXCEPT { *this = k; }
    
    /** Copy constructor */
    inline explicit PublicKeyBase(const MyPrivateKey &k) NOEXCEPT { *this = k; }

    /** Assignment from string */
    inline PublicKey &operator=(const FixedBlock<SER_BYTES> &b) NOEXCEPT {
        memcpy(pub_.data(),b.data(),b.size());
        return *this;
    }

    /** Assignment from private key */
    inline PublicKey &operator=(const PublicKey &p) NOEXCEPT {
        return *this = p.pub_;
    }

    /** Assignment from private key */
    inline PublicKey &operator=(const MyPrivateKey &p) NOEXCEPT {
        return *this = p.pub_;
    }

    /** Serialization size. */
    inline size_t ser_size() const NOEXCEPT { return SER_BYTES; }
    
    /** Serialize into a buffer. */
    inline void serialize_into(unsigned char *x) const NOEXCEPT {
        memcpy(x,pub_.data(), pub_.size());
    }
}; /* class PublicKey */

}; /* template<> struct EdDSA<$(cxx_ns)> */

#undef NOEXCEPT
} /* namespace decaf */
