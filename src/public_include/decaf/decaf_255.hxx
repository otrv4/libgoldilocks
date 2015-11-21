/**
 * @file decaf/decaf_255.hxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief A group of prime order p, C++ wrapper.
 *
 * The Decaf library implements cryptographic operations on a an elliptic curve
 * group of prime order p.  It accomplishes this by using a twisted Edwards
 * curve (isogenous to Curve25519) and wiping out the cofactor.
 *
 * The formulas are all complete and have no special cases, except that
 * decaf_255_decode can fail because not every sequence of bytes is a valid group
 * element.
 *
 * The formulas contain no data-dependent branches, timing or memory accesses,
 * except for decaf_255_base_double_scalarmul_non_secret.
 */
#ifndef __DECAF_255_HXX__
#define __DECAF_255_HXX__ 1

/** This code uses posix_memalign. */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600 
#endif
#include <stdlib.h>
#include <string.h> /* for memcpy */

#include <decaf.h>
#include <decaf/secure_buffer.hxx>
#include <string>
#include <sys/types.h>
#include <limits.h>

/** @cond internal */
#if __cplusplus >= 201103L
#define NOEXCEPT noexcept
#else
#define NOEXCEPT throw()
#endif
/** @endcond */

namespace decaf {

/**
 * @brief Curve25519/Decaf instantiation of group.
 */
struct IsoEd25519 {
    
/** The name of the curve */
static inline const char *name() { return "IsoEd25519"; }

/** The curve's cofactor (removed, but useful for testing) */
static const int REMOVED_COFACTOR = 8;

/** Residue class of field modulus: p == this mod 2*(this-1) */
static const int FIELD_MODULUS_TYPE = 5;

/** @cond internal */
class Point;
class Precomputed;
/** @endcond */

/**
 * @brief A scalar modulo the curve order.
 * Supports the usual arithmetic operations, all in constant time.
 * FIXME: make it clearer which init-from-buffer operations reject scalars that are too big.
 */
class Scalar : public Serializable<Scalar> {
private:
    /** @brief wrapped C type */
    typedef decaf_255_scalar_t Wrapped;
    
public:
    /** @brief Size of a serialized element */
    static const size_t SER_BYTES = DECAF_255_SCALAR_BYTES;
    
    /** @brief access to the underlying scalar object */
    Wrapped s;
    
    /** @brief Don't initialize. */
    inline Scalar(const NOINIT &) NOEXCEPT {}
    
    /** @brief Set to an unsigned word */
    inline Scalar(const decaf_word_t w) NOEXCEPT { *this = w; }

    /** @brief Set to a signed word */
    inline Scalar(const int w) NOEXCEPT { *this = w; } 
    
    /** @brief Construct from RNG */
    inline explicit Scalar(Rng &rng) NOEXCEPT {
        FixedArrayBuffer<SER_BYTES> sb(rng);
        *this = sb;
    }
    
    /** @brief Construct from decaf_scalar_t object. */
    inline Scalar(const Wrapped &t = decaf_255_scalar_zero) NOEXCEPT {  decaf_255_scalar_copy(s,t); } 
    
    /** @brief Copy constructor. */
    inline Scalar(const Scalar &x) NOEXCEPT {  *this = x; }
    
    /** @brief Construct from arbitrary-length little-endian byte sequence. */
    inline Scalar(const Block &buffer) NOEXCEPT { *this = buffer; }

    /** @brief Serializable instance */
    inline size_t serSize() const NOEXCEPT { return SER_BYTES; }
    
    /** @brief Serializable instance */
    inline void serializeInto(unsigned char *buffer) const NOEXCEPT {
        decaf_255_scalar_encode(buffer, s);
    }
    
    /** @brief Assignment. */
    inline Scalar& operator=(const Scalar &x) NOEXCEPT {  decaf_255_scalar_copy(s,x.s); return *this; }
    
    /** @brief Assign from unsigned word. */
    inline Scalar& operator=(decaf_word_t w) NOEXCEPT {  decaf_255_scalar_set_unsigned(s,w); return *this; }
    
    /** @brief Assign from signed int. */
    inline Scalar& operator=(int w) NOEXCEPT {
        Scalar t(-(decaf_word_t)INT_MIN);
        decaf_255_scalar_set_unsigned(s,(decaf_word_t)w - (decaf_word_t)INT_MIN);
        *this -= t;
        return *this;
    }
    
    /** Destructor securely zeorizes the scalar. */
    inline ~Scalar() NOEXCEPT { decaf_255_scalar_destroy(s); }
    
    /** @brief Assign from arbitrary-length little-endian byte sequence in a Block. */
    inline Scalar &operator=(const Block &bl) NOEXCEPT {
        decaf_255_scalar_decode_long(s,bl.data(),bl.size()); return *this;
    }
    
    /**
     * @brief Decode from correct-length little-endian byte sequence.
     * @return DECAF_FAILURE if the scalar is greater than or equal to the group order q.
     */
    static inline decaf_error_t __attribute__((warn_unused_result)) decode (
        Scalar &sc, const FixedBlock<SER_BYTES> buffer
    ) NOEXCEPT {
        return decaf_255_scalar_decode(sc.s,buffer.data());
    }
    
    /** Add. */
    inline Scalar  operator+ (const Scalar &q) const NOEXCEPT { Scalar r((NOINIT())); decaf_255_scalar_add(r.s,s,q.s); return r; }
    
    /** Add to this. */
    inline Scalar &operator+=(const Scalar &q)       NOEXCEPT { decaf_255_scalar_add(s,s,q.s); return *this; }
    
    /** Subtract. */
    inline Scalar  operator- (const Scalar &q) const NOEXCEPT { Scalar r((NOINIT())); decaf_255_scalar_sub(r.s,s,q.s); return r; }
    
    /** Subtract from this. */
    inline Scalar &operator-=(const Scalar &q)       NOEXCEPT { decaf_255_scalar_sub(s,s,q.s); return *this; }
    
    /** Multiply */
    inline Scalar  operator* (const Scalar &q) const NOEXCEPT { Scalar r((NOINIT())); decaf_255_scalar_mul(r.s,s,q.s); return r; }
    
    /** Multiply into this. */
    inline Scalar &operator*=(const Scalar &q)       NOEXCEPT { decaf_255_scalar_mul(s,s,q.s); return *this; }
    
    /** Negate */
    inline Scalar operator- ()                const NOEXCEPT { Scalar r((NOINIT())); decaf_255_scalar_sub(r.s,decaf_255_scalar_zero,s); return r; }
    
    /** @brief Invert with Fermat's Little Theorem (slow!).  If *this == 0, return 0. */
    inline Scalar inverse() const throw(CryptoException) {
        Scalar r;
        if (DECAF_SUCCESS != decaf_255_scalar_invert(r.s,s)) {
            throw CryptoException();
        }
        return r;
    }
    
    /** @brief Divide by inverting q. If q == 0, return 0.  */
    inline Scalar operator/ (const Scalar &q) const throw(CryptoException) { return *this * q.inverse(); }
    
    /** @brief Divide by inverting q. If q == 0, return 0.  */
    inline Scalar &operator/=(const Scalar &q) throw(CryptoException) { return *this *= q.inverse(); }
    
    /** @brief Compare in constant time */
    inline bool   operator!=(const Scalar &q) const NOEXCEPT { return !(*this == q); }
    
    /** @brief Compare in constant time */
    inline bool   operator==(const Scalar &q) const NOEXCEPT { return !!decaf_255_scalar_eq(s,q.s); }
    
    /** @brief Scalarmul with scalar on left. */
    inline Point operator* (const Point &q) const NOEXCEPT { return q * (*this); }
    
    /** @brief Scalarmul-precomputed with scalar on left. */
    inline Point operator* (const Precomputed &q) const NOEXCEPT { return q * (*this); }
    
    /** @brief Direct scalar multiplication. */
    inline SecureBuffer direct_scalarmul(
        const Block &in,
        decaf_bool_t allow_identity=DECAF_FALSE,
        decaf_bool_t short_circuit=DECAF_TRUE    
    ) const throw(CryptoException);
};

/**
 * @brief Element of prime-order group.
 */
class Point : public Serializable<Point> {
public:
    typedef decaf_255_point_t Wrapped;
    
    /** @brief Size of a serialized element */
    static const size_t SER_BYTES = DECAF_255_SER_BYTES;
    
    /** @brief Bytes required for hash */
    static const size_t HASH_BYTES = SER_BYTES;
    
    /** @brief Size of a stegged element */
    static const size_t STEG_BYTES = HASH_BYTES * 2;
    
    /** The c-level object. */
    Wrapped p;
    
    /** @brief Don't initialize. */
    inline Point(const NOINIT &) NOEXCEPT {}
    
    /** @brief Constructor sets to identity by default. */
    inline Point(const Wrapped &q = decaf_255_point_identity) NOEXCEPT { decaf_255_point_copy(p,q); }
    
    /** @brief Copy constructor. */
    inline Point(const Point &q) NOEXCEPT { *this = q; }
    
    /** @brief Assignment. */
    inline Point& operator=(const Point &q) NOEXCEPT { decaf_255_point_copy(p,q.p); return *this; }
    
    /** @brief Destructor securely zeorizes the point. */
    inline ~Point() NOEXCEPT { decaf_255_point_destroy(p); }
    
    /** @brief Construct from RNG */
    inline explicit Point(Rng &rng, bool uniform = true) NOEXCEPT {
        if (uniform) {
            FixedArrayBuffer<2*HASH_BYTES> b(rng);
            set_to_hash(b);
        } else {
            FixedArrayBuffer<HASH_BYTES> b(rng);
            set_to_hash(b);
        }
    }
   
   /**
    * @brief Initialize from a fixed-length byte string.
     * The all-zero string maps to the identity.
     *
    * @throw CryptoException the string was the wrong length, or wasn't the encoding of a point,
    * or was the identity and allow_identity was DECAF_FALSE.
    */
    inline explicit Point(const FixedBlock<SER_BYTES> &buffer, decaf_bool_t allow_identity=DECAF_TRUE)
        throw(CryptoException) {
        if (DECAF_SUCCESS != decode(*this,buffer,allow_identity)) {
            throw CryptoException();
        }
    }

    /**
     * @brief Initialize from C++ fixed-length byte string.
     * The all-zero string maps to the identity.
     *
     * @retval DECAF_SUCCESS the string was successfully decoded.
     * @return DECAF_FAILURE the string was the wrong length, or wasn't the encoding of a point,
     * or was the identity and allow_identity was DECAF_FALSE.  Contents of the buffer are undefined.
     */    
    static inline decaf_error_t __attribute__((warn_unused_result)) decode (
        Point &p, const FixedBlock<SER_BYTES> &buffer, decaf_bool_t allow_identity=DECAF_TRUE
    ) NOEXCEPT {
        return decaf_255_point_decode(p.p,buffer.data(),allow_identity);
    }
   
    /**
     * @brief Map uniformly to the curve from a hash buffer.
     * The empty or all-zero string maps to the identity, as does the string "\x01".
     * If the buffer is shorter than 2*HASH_BYTES, well, it won't be as uniform,
     * but the buffer will be zero-padded on the right.
     */
    static inline Point from_hash ( const Block &s ) NOEXCEPT {
        Point p((NOINIT())); p.set_to_hash(s); return p;
    }

   /**
    * @brief Map to the curve from a hash buffer.
    * The empty or all-zero string maps to the identity, as does the string "\x01".
    * If the buffer is shorter than 2*HASH_BYTES, well, it won't be as uniform,
    * but the buffer will be zero-padded on the right.
    */
    inline void set_to_hash( const Block &s ) NOEXCEPT {
        if (s.size() < HASH_BYTES) {
            SecureBuffer b(HASH_BYTES);
            memcpy(b.data(), s.data(), s.size());
            decaf_255_point_from_hash_nonuniform(p,b.data());
        } else if (s.size() == HASH_BYTES) {
            decaf_255_point_from_hash_nonuniform(p,s.data());
        } else if (s.size() < 2*HASH_BYTES) {
            SecureBuffer b(2*HASH_BYTES);
            memcpy(b.data(), s.data(), s.size());
            decaf_255_point_from_hash_uniform(p,b.data());
        } else {
            decaf_255_point_from_hash_uniform(p,s.data());
        }
    }

    /** @brief Serializable instance */
    inline size_t serSize() const NOEXCEPT { return SER_BYTES; }
    
    /** @brief Serializable instance */
    inline void serializeInto(unsigned char *buffer) const NOEXCEPT {
        decaf_255_point_encode(buffer, p);
    }
    
    /** @brief Point add. */
    inline Point  operator+ (const Point &q)  const NOEXCEPT { Point r((NOINIT())); decaf_255_point_add(r.p,p,q.p); return r; }
    
    /** @brief Point add. */
    inline Point &operator+=(const Point &q)        NOEXCEPT { decaf_255_point_add(p,p,q.p); return *this; }
    
    /** @brief Point subtract. */
    inline Point  operator- (const Point &q)  const NOEXCEPT { Point r((NOINIT())); decaf_255_point_sub(r.p,p,q.p); return r; }
    
    /** @brief Point subtract. */
    inline Point &operator-=(const Point &q)        NOEXCEPT { decaf_255_point_sub(p,p,q.p); return *this; }
    
    /** @brief Point negate. */
    inline Point  operator- ()                const NOEXCEPT { Point r((NOINIT())); decaf_255_point_negate(r.p,p); return r; }
    
    /** @brief Double the point out of place. */
    inline Point  times_two ()                const NOEXCEPT { Point r((NOINIT())); decaf_255_point_double(r.p,p); return r; }
    
    /** @brief Double the point in place. */
    inline Point &double_in_place()                NOEXCEPT { decaf_255_point_double(p,p); return *this; }
    
    /** @brief Constant-time compare. */
    inline bool  operator!=(const Point &q)  const NOEXCEPT { return ! decaf_255_point_eq(p,q.p); }

    /** @brief Constant-time compare. */
    inline bool  operator==(const Point &q)  const NOEXCEPT { return !!decaf_255_point_eq(p,q.p); }
    
    /** @brief Scalar multiply. */
    inline Point  operator* (const Scalar &s) const NOEXCEPT { Point r((NOINIT())); decaf_255_point_scalarmul(r.p,p,s.s); return r; }
    
    /** @brief Scalar multiply in place. */
    inline Point &operator*=(const Scalar &s)       NOEXCEPT { decaf_255_point_scalarmul(p,p,s.s); return *this; }
    
    /** @brief Multiply by s.inverse().  If s=0, maps to the identity. */
    inline Point  operator/ (const Scalar &s) const throw(CryptoException) { return (*this) * s.inverse(); }
    
    /** @brief Multiply by s.inverse().  If s=0, maps to the identity. */
    inline Point &operator/=(const Scalar &s)       throw(CryptoException) { return (*this) *= s.inverse(); }
    
    /** @brief Validate / sanity check */
    inline bool validate() const NOEXCEPT { return decaf_255_point_valid(p); }
    
    /** @brief Double-scalar multiply, equivalent to q*qs + r*rs but faster. */
    static inline Point double_scalarmul (
        const Point &q, const Scalar &qs, const Point &r, const Scalar &rs
    ) NOEXCEPT {
        Point p((NOINIT())); decaf_255_point_double_scalarmul(p.p,q.p,qs.s,r.p,rs.s); return p;
    }
    
    /**
     * @brief Double-scalar multiply, equivalent to q*qs + r*rs but faster.
     * For those who like their scalars before the point.
     */
    static inline Point double_scalarmul (
        const Scalar &qs, const Point &q, const Scalar &rs, const Point &r
    ) NOEXCEPT {
        return double_scalarmul(q,qs,r,rs);
    }
    
    /**
     * @brief Double-scalar multiply: this point by the first scalar and base by the second scalar.
     * @warning This function takes variable time, and may leak the scalars (or points, but currently
     * it doesn't).
     */
    inline Point non_secret_combo_with_base(const Scalar &s, const Scalar &s_base) NOEXCEPT {
        Point r((NOINIT())); decaf_255_base_double_scalarmul_non_secret(r.p,s_base.s,p,s.s); return r;
    }
    
    /** @brief Return a point equal to *this, whose internal data is rotated by a torsion element. */
    inline Point debugging_torque() const NOEXCEPT {
        Point q; decaf_255_point_debugging_torque(q.p,p); return q;
    }
    
    /** @brief Return a point equal to *this, whose internal data has a modified representation. */
    inline Point debugging_pscale(const FixedBlock<SER_BYTES> factor) const NOEXCEPT {
        Point q; decaf_255_point_debugging_pscale(q.p,p,factor.data()); return q;
    }
    
    /** @brief Return a point equal to *this, whose internal data has a randomized representation. */
    inline Point debugging_pscale(Rng &r) const NOEXCEPT {
        FixedArrayBuffer<SER_BYTES> sb(r); return debugging_pscale(sb);
    }
    
    /**
     * Modify buffer so that Point::from_hash(Buffer) == *this, and return DECAF_SUCCESS;
     * or leave buf unmodified and return DECAF_FAILURE.
     */
    inline decaf_error_t invert_elligator (
        Buffer buf, uint16_t hint
    ) const NOEXCEPT {
        unsigned char buf2[2*HASH_BYTES];
        memset(buf2,0,sizeof(buf2));
        memcpy(buf2,buf.data(),(buf.size() > 2*HASH_BYTES) ? 2*HASH_BYTES : buf.size());
        decaf_bool_t ret;
        if (buf.size() > HASH_BYTES) {
            ret = decaf_successful(decaf_255_invert_elligator_uniform(buf2, p, hint));
        } else {
            ret = decaf_successful(decaf_255_invert_elligator_nonuniform(buf2, p, hint));
        }
        if (buf.size() < HASH_BYTES) {
            ret &= decaf_memeq(&buf2[buf.size()], &buf2[HASH_BYTES], HASH_BYTES - buf.size());
        }
        if (ret) {
            /* TODO: make this constant time?? */
            memcpy(buf.data(),buf2,(buf.size() < HASH_BYTES) ? buf.size() : HASH_BYTES);
        }
        decaf_bzero(buf2,sizeof(buf2));
        return decaf_succeed_if(ret);
    }
    
    /** @brief Steganographically encode this */
    inline SecureBuffer steg_encode(Rng &rng, size_t size=STEG_BYTES) const throw(std::bad_alloc, LengthException) {
        if (size <= HASH_BYTES + 4 || size > 2*HASH_BYTES) throw LengthException();
        SecureBuffer out(STEG_BYTES);
        decaf_error_t done;
        do {
            rng.read(Buffer(out).slice(HASH_BYTES-1,STEG_BYTES-HASH_BYTES+1));
            done = invert_elligator(out, out[HASH_BYTES-1]); 
        } while (!decaf_successful(done));
        return out;
    }
    
    /** @brief Return the base point */
    static inline const Point base() NOEXCEPT { return Point(decaf_255_point_base); }
    
    /** @brief Return the identity point */
    static inline const Point identity() NOEXCEPT { return Point(decaf_255_point_identity); }
};

/**
 * @brief Precomputed table of points.
 * Minor difficulties arise here because the decaf API doesn't expose, as a constant, how big such an object is.
 * Therefore we have to call malloc() or friends, but that's probably for the best, because you don't want to
 * stack-allocate a 15kiB object anyway.
 */

/** @cond internal */
typedef decaf_255_precomputed_s Precomputed_U;
/** @endcond */
class Precomputed
    /** @cond internal */
    : protected OwnedOrUnowned<Precomputed,Precomputed_U>
    /** @endcond */
{
public:
    
    /** Destructor securely zeorizes the memory. */
    inline ~Precomputed() NOEXCEPT { clear(); }
    
    /**
     * @brief Initialize from underlying type, declared as a reference to prevent
     * it from being called with 0, thereby breaking override.
     *
     * The underlying object must remain valid throughout the lifetime of this one.
     *
     * By default, initializes to the table for the base point.
     *
     * @warning The empty initializer makes this equal to base, unlike the empty
     * initializer for points which makes this equal to the identity.
     */ 
    inline Precomputed (
        const Precomputed_U &yours = *defaultValue()
    ) NOEXCEPT : OwnedOrUnowned<Precomputed,Precomputed_U>(yours) {}
    

#if __cplusplus >= 201103L
    /** @brief Move-assign operator */
    inline Precomputed &operator=(Precomputed &&it) NOEXCEPT {
        OwnedOrUnowned<Precomputed,Precomputed_U>::operator= (it);
        return *this;
    }
    
    /** @brief Move constructor */
    inline Precomputed(Precomputed &&it) NOEXCEPT : OwnedOrUnowned<Precomputed,Precomputed_U>() {
        *this = it;
    }
    
    /** @brief Undelete copy operator */
    inline Precomputed &operator=(const Precomputed &it) NOEXCEPT {
        OwnedOrUnowned<Precomputed,Precomputed_U>::operator= (it);
        return *this;
    }
#endif
    
    /**
     * @brief Initilaize from point.  Must allocate memory, and may throw.
     */
    inline Precomputed &operator=(const Point &it) throw(std::bad_alloc) {
        alloc();
        decaf_255_precompute(ours.mine,it.p);
        return *this;
    }
    
    /**
     * @brief Copy constructor.
     */
    inline Precomputed(const Precomputed &it) throw(std::bad_alloc) 
        : OwnedOrUnowned<Precomputed,Precomputed_U>() { *this = it; }
   
    /**
     * @brief Constructor which initializes from point.
     */
    inline explicit Precomputed(const Point &it) throw(std::bad_alloc)
        : OwnedOrUnowned<Precomputed,Precomputed_U>() { *this = it; }
    
    /** @brief Fixed base scalarmul. */
    inline Point operator* (const Scalar &s) const NOEXCEPT { Point r; decaf_255_precomputed_scalarmul(r.p,get(),s.s); return r; }
    
    /** @brief Multiply by s.inverse().  If s=0, maps to the identity. */
    inline Point operator/ (const Scalar &s) const throw(CryptoException) { return (*this) * s.inverse(); }
    
    /** @brief Return the table for the base point. */
    static inline const Precomputed base() NOEXCEPT { return Precomputed(); }

public:
    /** @cond internal */
    friend class OwnedOrUnowned<Precomputed,Precomputed_U>;
    static inline size_t size() NOEXCEPT { return sizeof_decaf_255_precomputed_s; }
    static inline size_t alignment() NOEXCEPT { return alignof_decaf_255_precomputed_s; }
    static inline const Precomputed_U * defaultValue() NOEXCEPT { return decaf_255_precomputed_base; }
    /** @endcond */
};

}; /* struct IsoEd25519 */



/** @cond internal */
inline SecureBuffer IsoEd25519::Scalar::direct_scalarmul (
    const Block &in,
    decaf_bool_t allow_identity,
    decaf_bool_t short_circuit
) const throw(CryptoException) {
    SecureBuffer out(IsoEd25519::Point::SER_BYTES);
    if (DECAF_SUCCESS !=
        decaf_255_direct_scalarmul(out.data(), in.data(), s, allow_identity, short_circuit)
    ) {
        throw CryptoException();
    }
    return out;
}
/** endcond */

#undef NOEXCEPT
} /* namespace decaf */

#endif /* __DECAF_255_HXX__ */
