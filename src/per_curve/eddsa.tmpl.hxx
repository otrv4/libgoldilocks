
/*
 * Example Decaf cyrpto routines, C++ wrapper.
 * @warning These are merely examples, though they ought to be secure.  But real
 * protocols will decide differently on magic numbers, formats, which items to
 * hash, etc.
 * @warning Experimental!  The names, parameter orders etc are likely to change.
 */

#include <decaf/decaf_$(gf_bits).hxx>
#include <decaf/eddsa_$(gf_bits).h>

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
class PrivateKey;
class PublicKey;
/** @endcond */

/** Prehash context for EdDSA.  TODO: test me! */
class Prehash : public $(re.sub(r"SHAKE(\d+)",r"SHAKE<\1>", eddsa_hash.upper())) {
public:
    /** Do we support contexts for signatures?  If not, they must always be NULL */
    static const bool SUPPORTS_CONTEXTS = $(C_NS)_EDDSA_SUPPORTS_CONTEXTS;
    
private:
    typedef $(re.sub(r"SHAKE(\d+)",r"SHAKE<\1>", eddsa_hash.upper())) Super;
    SecureBuffer context_;
    friend class PrivateKey;
    friend class PublicKey;
    
    void init() throw(LengthException) {
        Super::reset();
        
        if (context_.size() > 255
            || (context_.size() != 0 && !SUPPORTS_CONTEXTS)
        ) {
            throw LengthException();
        }
        
        if (SUPPORTS_CONTEXTS) {
            uint8_t dom[2] = {2, context_.size() };
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

class PrivateKey : public Serializable<PrivateKey>  {
private:
/** @cond internal */
    friend class PublicKey;
/** @endcond */
    
    /** The pre-expansion form of the signing key. */
    FixedArrayBuffer<$(C_NS)_EDDSA_PRIVATE_BYTES> priv_;
    
    /** The post-expansion public key. */
    FixedArrayBuffer<$(C_NS)_EDDSA_PUBLIC_BYTES> pub_;
    
public:
    /** Underlying group */
    typedef $(cxx_ns) Group;
    
    /** Signature size. */
    static const size_t SIG_BYTES = $(C_NS)_EDDSA_SIGNATURE_BYTES;
    
    /** Serialization size. */
    static const size_t SER_BYTES = $(C_NS)_EDDSA_PRIVATE_BYTES;
    
    /** Do we support contexts for signatures?  If not, they must always be NULL */
    static const bool SUPPORTS_CONTEXTS = $(C_NS)_EDDSA_SUPPORTS_CONTEXTS;
    
    
    /** Create but don't initialize */
    inline explicit PrivateKey(const NOINIT&) NOEXCEPT : priv_((NOINIT())), pub_((NOINIT())) { }
    
    /** Read a private key from a string */
    inline explicit PrivateKey(const FixedBlock<SER_BYTES> &b) NOEXCEPT { *this = b; }
    
    /** Copy constructor */
    inline PrivateKey(const PrivateKey &k) NOEXCEPT { *this = k; }
    
    /** Create at random */
    inline explicit PrivateKey(Rng &r) NOEXCEPT : priv_(r) {
        $(c_ns)_eddsa_derive_public_key(pub_.data(), priv_.data());
    }
    
    /** Assignment from string */
    inline PrivateKey &operator=(const FixedBlock<SER_BYTES> &b) NOEXCEPT {
        memcpy(priv_.data(),b.data(),b.size());
        $(c_ns)_eddsa_derive_public_key(pub_.data(), priv_.data());
        return *this;
    }
    
    /** Copy assignment */
    inline PrivateKey &operator=(const PrivateKey &k) NOEXCEPT {
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
    inline PublicKey pub() const NOEXCEPT {
        PublicKey pub(*this);
        return pub;
    }
    
    /**
     * Sign a message.
     * @param [in] message The message to be signed.
     * @param [in] prehashed If true, the message to be signed is already hashed.
     * @param [in] context A context for the signature; must be at most 255 bytes;
     * must be absent if SUPPORTS_CONTEXTS == false.
     *
     * @warning It is generally unsafe to use Ed25519 with both prehashed and non-prehashed messages.
     */
    inline SecureBuffer sign (
        const Block &message,
        bool prehashed = false,
        const Block &context = Block(NULL,0)
    ) const throw(LengthException, std::bad_alloc) {
        if (context.size() > 255
            || (context.size() != 0 && !SUPPORTS_CONTEXTS)
        ) {
            throw LengthException();
        }
        
        SecureBuffer out(SIG_BYTES);
        $(c_ns)_eddsa_sign (
            out.data(),
            priv_.data(),
            pub_.data(),
            message.data(),
            message.size(),
            prehashed
#if $(C_NS)_EDDSA_SUPPORTS_CONTEXTS
            , context.data(),
            context.size()
#endif
        );
        return out;
    }

    /* Sign a prehash context, and reset the context */
    inline SecureBuffer sign ( Prehash &ph ) const throw(std::bad_alloc) {
        FixedArrayBuffer<Prehash::OUTPUT_BYTES> m;
        ph.final(m);
        return sign(m, true, ph.context_);
    }
}; /* class PrivateKey */

class PublicKey : public Serializable<PublicKey> {
private:
/** @cond internal */
    friend class PrivateKey;
/** @endcond */

public:
    /** The pre-expansion form of the signature */
    FixedArrayBuffer<$(C_NS)_EDDSA_PUBLIC_BYTES> pub_;
    
    /* PERF FUTURE: Pre-cached decoding? Precomputed table?? */
    
public:
    /** Underlying group */
    typedef $(cxx_ns) Group;
    
    /** Signature size. */
    static const size_t SIG_BYTES = $(C_NS)_EDDSA_SIGNATURE_BYTES;
    
    /** Serialization size. */
    static const size_t SER_BYTES = $(C_NS)_EDDSA_PRIVATE_BYTES;
    
    /** Do we support contexts for signatures?  If not, they must always be NULL */
    static const bool SUPPORTS_CONTEXTS = $(C_NS)_EDDSA_SUPPORTS_CONTEXTS;
    
    
    /** Create but don't initialize */
    inline explicit PublicKey(const NOINIT&) NOEXCEPT : pub_((NOINIT())) { }
    
    /** Read a private key from a string */
    inline explicit PublicKey(const FixedBlock<SER_BYTES> &b) NOEXCEPT { *this = b; }
    
    /** Copy constructor */
    inline PublicKey(const PublicKey &k) NOEXCEPT { *this = k; }
    
    /** Copy constructor */
    inline explicit PublicKey(const PrivateKey &k) NOEXCEPT { *this = k; }

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
    inline PublicKey &operator=(const PrivateKey &p) NOEXCEPT {
        return *this = p.pub_;
    }

    
    /** Serialization size. */
    inline size_t ser_size() const NOEXCEPT { return SER_BYTES; }
    
    /** Serialize into a buffer. */
    inline void serialize_into(unsigned char *x) const NOEXCEPT {
        memcpy(x,pub_.data(), pub_.size());
    }
    
    /** Verify a signature, returning DECAF_FAILURE if verification fails */
    inline decaf_error_t WARN_UNUSED verify_noexcept (
        const FixedBlock<SIG_BYTES> &sig,
        const Block &message,
        bool prehashed = false,
        const Block &context = Block(NULL,0)
    ) const NOEXCEPT {
        if (context.size() > 255
            || (context.size() != 0 && !SUPPORTS_CONTEXTS)
        ) {
            return DECAF_FAILURE;
        }
        
        return $(c_ns)_eddsa_verify (
            sig.data(),
            pub_.data(),
            message.data(),
            message.size(),
            prehashed
#if $(C_NS)_EDDSA_SUPPORTS_CONTEXTS
            , context.data(),
            context.size()
#endif
        );
    }
    
    /** Verify a signature, throwing an exception if verification fails
     * @param [in] sig The signature.
     * @param [in] message The signed message.
     * @param [in] prehashed If true, the message is already hashed.
     * @param [in] context A context for the signature; must be at most 255 bytes;
     * must be absent if SUPPORTS_CONTEXTS == false.
     *
     * @warning It is generally unsafe to use Ed25519 with both prehashed and non-prehashed messages.
     */
    inline void verify (
        const FixedBlock<SIG_BYTES> &sig,
        const Block &message,
        bool prehashed = false,
        const Block &context = Block(NULL,0)
    ) const throw(LengthException,CryptoException) {
        if (context.size() > 255
            || (context.size() != 0 && !SUPPORTS_CONTEXTS)
        ) {
            throw LengthException();
        }
        
        if (DECAF_SUCCESS != verify_noexcept( sig, message, prehashed, context )) {
            throw CryptoException();
        }
    }
    
    /* Verify a prehash context, and reset the context */
    inline decaf_error_t WARN_UNUSED verify_noexcept (
        const FixedBlock<SIG_BYTES> &sig,
        Prehash &ph
    ) const NOEXCEPT {
        FixedArrayBuffer<Prehash::OUTPUT_BYTES> m;
        ph.final(m);
        return verify_noexcept(sig, m, true, ph.context_);
    }
    
    /* Verify a prehash context, and reset the context */
    inline void verify (
        const FixedBlock<SIG_BYTES> &sig,
        Prehash &ph
    ) const throw(CryptoException) {
        FixedArrayBuffer<Prehash::OUTPUT_BYTES> m;
        ph.final(m);
        verify(sig, m, true, ph.context_);
    }
}; /* class PublicKey */

}; /* template<> struct EdDSA<$(cxx_ns)> */

#undef NOEXCEPT
} /* namespace decaf */
