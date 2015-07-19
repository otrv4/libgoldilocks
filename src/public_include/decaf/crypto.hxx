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
template <typename Group> class PublicKey {
private:
    /** @cond internal */
    friend class PrivateKey<Group>;
    //const typename Group::Point p;
    const FixedArrayBuffer<Group::Point::SER_BYTES> ser;
    static const size_t CHALLENGE_BYTES = Group::Scalar::SER_BYTES;
    /** @endcond */

public:
    /** SHAKE instance size for sigs etc */
    static const size_t SHAKE_BITS = 256;
    
    /** Size of a signature */
    static const size_t SIG_BYTES = Group::Point::SER_BYTES + Group::Scalar::SER_BYTES;
    
    /** @brief Return a pointer to the serialized version of the point. */
    inline operator FixedBlock<Group::Point::SER_BYTES>() const NOEXCEPT {
        return ser;
    }
    
    /** @brief Set the public key to a point */
    inline explicit PublicKey(const typename Group::Point &p) NOEXCEPT : ser(SecureBuffer(p)) {}
    
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
        SecureBuffer challenge(ctx.output(CHALLENGE_BYTES));
        
        const typename Group::Point combo = point().non_secret_combo_with_base(
            typename Group::Scalar(challenge),
            sig.slice(Group::Point::SER_BYTES, Group::Scalar::SER_BYTES)
        );
        if (combo != typename Group::Point(sig.slice(0,Group::Point::SER_BYTES)))
            throw CryptoException();
    }
    

    
    /** @brief Sign from a message. */
    inline void verify(const Block &message, const FixedBlock<SIG_BYTES> &sig) throw(CryptoException) {
        SHAKE<SHAKE_BITS> ctx;
        ctx << message;
        verify_shake(ctx,sig);
    }
};

/** @brief A private key using a particular EC group */ 
template <typename Group> class PrivateKey {
public:
    /** Size of associated symmetric key */
    static const size_t SYM_BYTES = 32;
    
    /** SHAKE instance size for sigs etc */
    static const size_t SHAKE_BITS = PublicKey<Group>::SHAKE_BITS;
    
private:
    /** @cond internal */
    static const size_t SCALAR_HASH_BYTES = Group::Scalar::SER_BYTES + 8;
    friend class PublicKey<Group>;
    const FixedArrayBuffer<SYM_BYTES> sym;
    const typename Group::Scalar scalar;
    const PublicKey<Group> pub_;
    /** @endcond */
    
public:
    /** @brief Construct at random */
    inline PrivateKey(Rng &r) :
        sym(r),
        scalar(SHAKE<SHAKE_BITS>::hash(sym, SCALAR_HASH_BYTES)),
        pub_(SecureBuffer(Group::Precomputed::base() * scalar)) {}
        
    /** @brief Construct from buffer */
    inline PrivateKey(const FixedBlock<SYM_BYTES> &sym_) :
        sym(sym_),
        scalar(SHAKE<SHAKE_BITS>::hash(sym, SCALAR_HASH_BYTES)),
        pub_(SecureBuffer(Group::Precomputed::Base * scalar)) {}
        
    /** @brief Compressed representation */
    inline const FixedBlock<SYM_BYTES> &ser_compressed() const NOEXCEPT {
        return sym;
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
    inline SecureBuffer sign_shake(const SHAKE<SHAKE_BITS> &ctx_) NOEXCEPT {
        SHAKE<SHAKE_BITS> ctx(ctx_);
        ctx << sym << "decaf_255_sign_shake";
        typename Group::Scalar nonce(ctx.output(SCALAR_HASH_BYTES));
        SecureBuffer g_nonce(Group::Precomputed::base() * nonce); /* FIXME: make output fixed size, avoid std::bad_alloc */
        
        ctx = ctx_;
        ctx << pub_.ser << g_nonce;
        SecureBuffer challenge(ctx.output(PublicKey<Group>::CHALLENGE_BYTES));
        SecureBuffer response((nonce - scalar * typename Group::Scalar(challenge)).encode());
        
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

