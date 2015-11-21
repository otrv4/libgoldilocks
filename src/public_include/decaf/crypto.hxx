/**
 * @file decaf/crypto.hxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Example cryptography using Decaf
 */
#ifndef __DECAF_CRYPTO_HXX__
#define __DECAF_CRYPTO_HXX__ 1

#include <decaf.hxx>
#include <decaf/shake.hxx>

/** @cond internal */
#if __cplusplus >= 201103L
#define NOEXCEPT noexcept
#else
#define NOEXCEPT throw()
#endif
/** @endcond */

/* TODO: decide on copy vs reference */

namespace decaf {
    
template <typename Group> class PrivateKey;

/** @brief A public key using a particular EC group */ 
template <typename Group> class PublicKey : public Serializable<PublicKey<Group> > {
private:
    /** @cond internal */
    friend class PrivateKey<Group>;
    static const size_t CHALLENGE_BYTES = Group::Scalar::SER_BYTES;
    //const typename Group::Point p;
    FixedArrayBuffer<Group::Point::SER_BYTES> ser;
    /** @endcond */

public:
    
    /** Create without init */
    PublicKey(NOINIT) : ser(NOINIT()) {}
    
    /** SHAKE instance size for sigs etc */
    static const size_t SHAKE_BITS = 256;
    
    /** Size of a signature */
    static const size_t SIG_BYTES = Group::Point::SER_BYTES + Group::Scalar::SER_BYTES;
    
    /** @brief Set the public key to a point */
    inline explicit PublicKey(const typename Group::Point &p) NOEXCEPT : ser(p.serialize()) {}
    
    /** @brief Get the private key for a given public key */
    inline explicit PublicKey(const PrivateKey<Group> &priv) NOEXCEPT;
    
    /** @brief Read a private key from a string*/
    inline explicit PublicKey(const FixedBlock<Group::Point::SER_BYTES> &b) NOEXCEPT : ser(b) {}
    
    /** @brief Return the corresponding EC point */
    inline typename Group::Point point() const throw(CryptoException) {
        return typename Group::Point(ser);
    }
    
    /** @brief Verify a sig.  TODO: nothrow version? */
    inline void verify_shake(const SHAKE<SHAKE_BITS> &ctx_, const FixedBlock<SIG_BYTES> &sig) throw(CryptoException) {
        SHAKE<SHAKE_BITS> ctx(ctx_);
        ctx << ser << sig.slice(0,Group::Point::SER_BYTES);
        FixedArrayBuffer<CHALLENGE_BYTES> challenge;
        ctx.output(challenge);
        
        typename Group::Scalar response;
        decaf_error_t scalar_OK = Group::Scalar::decode(
            response,
            sig.slice(Group::Point::SER_BYTES, Group::Scalar::SER_BYTES)
        );
            
        const typename Group::Point combo = point().non_secret_combo_with_base(
            typename Group::Scalar(challenge), response
        );
        if (!decaf_successful(scalar_OK)
            || combo != typename Group::Point(sig.slice(0,Group::Point::SER_BYTES)))
           throw CryptoException();
        //return scalar_OK & (combo == typename Group::Point(sig.slice(0,Group::Point::SER_BYTES)));
    }
    
    /** @brief Sign from a message. */
    inline void verify(const Block &message, const FixedBlock<SIG_BYTES> &sig) throw(CryptoException) {
        SHAKE<SHAKE_BITS> ctx;
        ctx << message;
        verify_shake(ctx,sig);
    }
    
    /** @brief Serialize into a buffer. */
    inline void serializeInto(unsigned char *x) const NOEXCEPT {
        memcpy(x,ser.data(),Group::Point::SER_BYTES);
    }
    
    /** @brief Serialize into a buffer. */
    inline size_t serSize() const NOEXCEPT {
        return Group::Point::SER_BYTES;
    }
    
    /** @brief Copy operator */
    inline PublicKey &operator=(const PublicKey &x) NOEXCEPT { ser = x.ser; return *this; }
};

/** @brief A private key using a particular EC group */ 
template <typename Group> class PrivateKey : public Serializable<PrivateKey<Group> > {
public:
    /** Size of associated symmetric key */
    static const size_t SYM_BYTES = 32;
    
    /** SHAKE instance size for sigs etc */
    static const size_t SHAKE_BITS = PublicKey<Group>::SHAKE_BITS;
    
private:
    /** @cond internal */
    static const size_t SCALAR_HASH_BYTES = Group::Scalar::SER_BYTES + 8;
    friend class PublicKey<Group>;
    FixedArrayBuffer<SYM_BYTES> sym;
    typename Group::Scalar scalar;
    PublicKey<Group> pub_;
    /** @endcond */
    
public:
    /** @brief Don't initialize */
    inline PrivateKey(const NOINIT &ni) NOEXCEPT : sym(ni), scalar(ni), pub_(ni) {}
        
    /** @brief Construct at random */
    inline PrivateKey(Rng &r) :
        sym(r),
        scalar(SHAKE<SHAKE_BITS>::hash(sym, SCALAR_HASH_BYTES)),
        pub_((Group::Precomputed::base() * scalar).serialize()) {}
        
    /** @brief Construct from buffer */
    inline PrivateKey(const FixedBlock<SYM_BYTES> &sym_) :
        sym(sym_),
        scalar(SHAKE<SHAKE_BITS>::hash(sym, SCALAR_HASH_BYTES)),
        pub_(SecureBuffer(Group::Precomputed::Base * scalar)) {}
        
    /** @brief Compressed representation */
    inline const FixedBlock<SYM_BYTES> &ser_compressed() const NOEXCEPT {
        return sym;
    }
    
    /** @brief Serialize */
    inline size_t serSize() const NOEXCEPT {
        return SYM_BYTES;
    }
    
    /** @brief Serialize */
    inline void serializeInto(unsigned char *target) const NOEXCEPT {
        memcpy(target,sym.data(),serSize());
    }
        
    /** @brief Uncompressed representation */
    inline SecureBuffer ser_uncompressed() const throw(std::bad_alloc) {
        SecureBuffer b(SYM_BYTES + Group::Scalar::SER_BYTES + Group::Point::SER_BYTES);
        Buffer(b).slice(0,SYM_BYTES).assign(sym);
        Buffer(b).slice(SYM_BYTES,Group::Scalar::SER_BYTES).assign(scalar);
        Buffer(b).slice(SYM_BYTES+Group::Scalar::SER_BYTES,Group::Point::SER_BYTES).assign(pub_.ser);
        return b;
    }
    
    /** @brief Sign from a SHAKE context.  TODO: double check random oracle eval of this; destructive version? */
    inline SecureBuffer sign_shake(const SHAKE<SHAKE_BITS> &ctx_) throw(std::bad_alloc) {
        SHAKE<SHAKE_BITS> ctx(ctx_);
        ctx << sym << "decaf_255_sign_shake";
        typename Group::Scalar nonce(ctx.output(SCALAR_HASH_BYTES));
        SecureBuffer g_nonce = (Group::Precomputed::base() * nonce).serialize();
        
        ctx = ctx_;
        ctx << pub_.ser << g_nonce;
        SecureBuffer challenge(ctx.output(PublicKey<Group>::CHALLENGE_BYTES));
        SecureBuffer response((nonce - scalar * typename Group::Scalar(challenge)).serialize());
        
        SecureBuffer ret(PublicKey<Group>::SIG_BYTES);
        Buffer(ret).slice(0,Group::Point::SER_BYTES).assign(g_nonce);
        Buffer(ret).slice(Group::Point::SER_BYTES, Group::Scalar::SER_BYTES).assign(response);
        return ret;
    }
    
    /** @brief Sign from a message. */
    inline SecureBuffer sign(const Block &message) {
        SHAKE<SHAKE_BITS> ctx;
        ctx << message;
        return sign_shake(ctx);
    }
    
    /** @brief Get the corresponding public key */
    inline const PublicKey<Group> &pub() const { return pub_; }
    
    /** @brief Copy operator */
    inline PrivateKey &operator=(const PrivateKey &x) NOEXCEPT {
        sym = x.sym;
        scalar = x.scalar;
        pub_ = x.pub_;
        return *this;
    }
};

/** @cond internal */
template <typename Group>
inline PublicKey<Group>::PublicKey(
    const PrivateKey<Group> &priv
) NOEXCEPT : ser(priv.pub_.ser){}
/** @endcond */

#undef NOEXCEPT
} /* namespace decaf */

#endif /* __DECAF_CRYPTO_HXX__ */

