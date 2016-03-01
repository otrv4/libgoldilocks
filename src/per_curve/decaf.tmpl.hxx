/**
 * A group of prime order p, C++ wrapper.
 * 
 * The Decaf library implements cryptographic operations on a an elliptic curve
 * group of prime order p. It accomplishes this by using a twisted Edwards
 * curve (isogenous to $(iso_to)) and wiping out the cofactor.
 * 
 * The formulas are all complete and have no special cases, except that
 * $(c_ns)_decode can fail because not every sequence of bytes is a valid group
 * element.
 * 
 * The formulas contain no data-dependent branches, timing or memory accesses,
 * except for $(c_ns)_base_double_scalarmul_non_secret.
 */

/** This code uses posix_memalign. */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif
#include <stdlib.h>
#include <string.h> /* for memcpy */

#include <decaf/decaf_$(gf_bits).h>
#include <decaf/eddsa_$(gf_bits).h>
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
 * $(iso_to)/Decaf instantiation of group.
 */
struct $(cxx_ns) {

/** The name of the curve */
static inline const char *name() { return "$(name)"; }

/** The curve's cofactor (removed, but useful for testing) */
static const int REMOVED_COFACTOR = $(cofactor);

/** Residue class of field modulus: p == this mod 2*(this-1) */
static const int FIELD_MODULUS_TYPE = $([2**i+1 for i in xrange(1,10) if modulus % 2**(i+1) != 1][0]);

/** @cond internal */
class Point;
class Precomputed;
/** @endcond */

/**
 * A scalar modulo the curve order.
 * Supports the usual arithmetic operations, all in constant time.
 */
class Scalar : public Serializable<Scalar> {
public:
    /** wrapped C type */
    typedef $(c_ns)_scalar_t Wrapped;
    
    /** Size of a serialized element */
    static const size_t SER_BYTES = $(C_NS)_SCALAR_BYTES;

    /** access to the underlying scalar object */
    Wrapped s;

    /** @cond internal */
    /** Don't initialize. */
    inline Scalar(const NOINIT &) NOEXCEPT {}
    /** @endcond */

    /** Set to an unsigned word */
    inline Scalar(uint64_t w) NOEXCEPT { *this = w; }

    /** Set to a signed word */
    inline Scalar(int64_t w) NOEXCEPT { *this = w; }

    /** Set to an unsigned word */
    inline Scalar(unsigned int w) NOEXCEPT { *this = w; }

    /** Set to a signed word */
    inline Scalar(int w) NOEXCEPT { *this = w; }

    /** Construct from RNG */
    inline explicit Scalar(Rng &rng) NOEXCEPT {
        FixedArrayBuffer<SER_BYTES + 16> sb(rng);
        *this = sb;
    }

    /** Construct from decaf_scalar_t object. */
    inline Scalar(const Wrapped &t = $(c_ns)_scalar_zero) NOEXCEPT { $(c_ns)_scalar_copy(s,t); }

    /** Copy constructor. */
    inline Scalar(const Scalar &x) NOEXCEPT { *this = x; }

    /** Construct from arbitrary-length little-endian byte sequence. */
    inline Scalar(const Block &buffer) NOEXCEPT { *this = buffer; }

    /** Serializable instance */
    inline size_t ser_size() const NOEXCEPT { return SER_BYTES; }

    /** Serializable instance */
    inline void serialize_into(unsigned char *buffer) const NOEXCEPT {
        $(c_ns)_scalar_encode(buffer, s);
    }

    /** Assignment. */
    inline Scalar& operator=(const Scalar &x) NOEXCEPT { $(c_ns)_scalar_copy(s,x.s); return *this; }

    /** Assign from unsigned 64-bit integer. */
    inline Scalar& operator=(uint64_t w) NOEXCEPT { $(c_ns)_scalar_set_unsigned(s,w); return *this; }


    /** Assign from signed int. */
    inline Scalar& operator=(int64_t w) NOEXCEPT {
        Scalar t(-(uint64_t)INT_MIN);
        $(c_ns)_scalar_set_unsigned(s,(uint64_t)w - (uint64_t)INT_MIN);
        *this -= t;
        return *this;
    }

    /** Assign from unsigned int. */
    inline Scalar& operator=(unsigned int w) NOEXCEPT { return *this = (uint64_t)w; }

    /** Assign from signed int. */
    inline Scalar& operator=(int w) NOEXCEPT { return *this = (int64_t)w; }

    /** Destructor securely zeorizes the scalar. */
    inline ~Scalar() NOEXCEPT { $(c_ns)_scalar_destroy(s); }

    /** Assign from arbitrary-length little-endian byte sequence in a Block. */
    inline Scalar &operator=(const Block &bl) NOEXCEPT {
        $(c_ns)_scalar_decode_long(s,bl.data(),bl.size()); return *this;
    }

    /**
     * Decode from correct-length little-endian byte sequence.
     * @return DECAF_FAILURE if the scalar is greater than or equal to the group order q.
     */
    static inline decaf_error_t WARN_UNUSED decode (
        Scalar &sc, const FixedBlock<SER_BYTES> buffer
    ) NOEXCEPT {
        return $(c_ns)_scalar_decode(sc.s,buffer.data());
    }

    /** Add. */
    inline Scalar operator+ (const Scalar &q) const NOEXCEPT { Scalar r((NOINIT())); $(c_ns)_scalar_add(r.s,s,q.s); return r; }

    /** Add to this. */
    inline Scalar &operator+=(const Scalar &q) NOEXCEPT { $(c_ns)_scalar_add(s,s,q.s); return *this; }

    /** Subtract. */
    inline Scalar operator- (const Scalar &q) const NOEXCEPT { Scalar r((NOINIT())); $(c_ns)_scalar_sub(r.s,s,q.s); return r; }

    /** Subtract from this. */
    inline Scalar &operator-=(const Scalar &q) NOEXCEPT { $(c_ns)_scalar_sub(s,s,q.s); return *this; }

    /** Multiply */
    inline Scalar operator* (const Scalar &q) const NOEXCEPT { Scalar r((NOINIT())); $(c_ns)_scalar_mul(r.s,s,q.s); return r; }

    /** Multiply into this. */
    inline Scalar &operator*=(const Scalar &q) NOEXCEPT { $(c_ns)_scalar_mul(s,s,q.s); return *this; }

    /** Negate */
    inline Scalar operator- () const NOEXCEPT { Scalar r((NOINIT())); $(c_ns)_scalar_sub(r.s,$(c_ns)_scalar_zero,s); return r; }

    /** Invert with Fermat's Little Theorem (slow!). If *this == 0,
     * throw CryptoException. */
    inline Scalar inverse() const throw(CryptoException) {
        Scalar r;
        if (DECAF_SUCCESS != $(c_ns)_scalar_invert(r.s,s)) {
            throw CryptoException();
        }
        return r;
    }

    /** Invert with Fermat's Little Theorem (slow!). If *this == 0, set r=0
     * and return DECAF_FAILURE. */
    inline decaf_error_t WARN_UNUSED
    inverse_noexcept(Scalar &r) const NOEXCEPT {
        return $(c_ns)_scalar_invert(r.s,s);
    }

    /** Divide by inverting q. If q == 0, return 0. */
    inline Scalar operator/ (const Scalar &q) const throw(CryptoException) { return *this * q.inverse(); }

    /** Divide by inverting q. If q == 0, return 0. */
    inline Scalar &operator/=(const Scalar &q) throw(CryptoException) { return *this *= q.inverse(); }

    /** Return half this scalar.  Much faster than /2. */
    inline Scalar half() const { Scalar out; $(c_ns)_scalar_halve(out.s,s); return out; }

    /** Compare in constant time */
    inline bool operator!=(const Scalar &q) const NOEXCEPT { return !(*this == q); }

    /** Compare in constant time */
    inline bool operator==(const Scalar &q) const NOEXCEPT { return !!$(c_ns)_scalar_eq(s,q.s); }

    /** Scalarmul with scalar on left. */
    inline Point operator* (const Point &q) const NOEXCEPT { return q * (*this); }

    /** Scalarmul-precomputed with scalar on left. */
    inline Point operator* (const Precomputed &q) const NOEXCEPT { return q * (*this); }

    /** Direct scalar multiplication. */
    inline SecureBuffer direct_scalarmul(
        const Block &in,
        decaf_bool_t allow_identity=DECAF_FALSE,
        decaf_bool_t short_circuit=DECAF_TRUE
    ) const throw(CryptoException);
};

/**
 * Element of prime-order group.
 */
class Point : public Serializable<Point> {
public:
    /** wrapped C type */
    typedef $(c_ns)_point_t Wrapped;
    
    /** Size of a serialized element */
    static const size_t SER_BYTES = $(C_NS)_SER_BYTES;

    /** Bytes required for hash */
    static const size_t HASH_BYTES = $(C_NS)_HASH_BYTES;

    /**
     * Size of a stegged element.
     * 
     * FUTURE: You can use HASH_BYTES * 3/2 (or more likely much less, eg HASH_BYTES + 8)
     * with a random oracle hash function, by hash-expanding everything past the first
     * HASH_BYTES of the element.  However, since the internal C invert_elligator is not
     * tied to a hash function, I didn't want to tie the C++ wrapper to a hash function
     * either.  But it might be a good idea to do this in the future, either with STROBE
     * or something else.
     *
     * Then again, calling invert_elligator at all is super niche, so maybe who cares?
     */
    static const size_t STEG_BYTES = HASH_BYTES * 2;
    
    /** Number of bits in invert_elligator which are actually used. */
    static const unsigned int INVERT_ELLIGATOR_WHICH_BITS = $(C_NS)_INVERT_ELLIGATOR_WHICH_BITS;

    /** The c-level object. */
    Wrapped p;

    /** @cond internal */
    /** Don't initialize. */
    inline Point(const NOINIT &) NOEXCEPT {}
    /** @endcond */

    /** Constructor sets to identity by default. */
    inline Point(const Wrapped &q = $(c_ns)_point_identity) NOEXCEPT { $(c_ns)_point_copy(p,q); }

    /** Copy constructor. */
    inline Point(const Point &q) NOEXCEPT { *this = q; }

    /** Assignment. */
    inline Point& operator=(const Point &q) NOEXCEPT { $(c_ns)_point_copy(p,q.p); return *this; }

    /** Destructor securely zeorizes the point. */
    inline ~Point() NOEXCEPT { $(c_ns)_point_destroy(p); }

    /** Construct from RNG */
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
    * Initialize from a fixed-length byte string.
    * The all-zero string maps to the identity.
    *
    * @throw CryptoException the string was the wrong length, or wasn't the encoding of a point,
    * or was the identity and allow_identity was DECAF_FALSE.
    */
    inline explicit Point(const FixedBlock<SER_BYTES> &buffer, decaf_bool_t allow_identity=DECAF_TRUE)
        throw(CryptoException) {
        if (DECAF_SUCCESS != decode(buffer,allow_identity)) {
            throw CryptoException();
        }
    }

    /**
     * Initialize from C++ fixed-length byte string.
     * The all-zero string maps to the identity.
     *
     * @retval DECAF_SUCCESS the string was successfully decoded.
     * @return DECAF_FAILURE the string was the wrong length, or wasn't the encoding of a point,
     * or was the identity and allow_identity was DECAF_FALSE. Contents of the buffer are undefined.
     */
    inline decaf_error_t WARN_UNUSED decode (
        const FixedBlock<SER_BYTES> &buffer, decaf_bool_t allow_identity=DECAF_TRUE
    ) NOEXCEPT {
        return $(c_ns)_point_decode(p,buffer.data(),allow_identity);
    }

    /**
     * Initialize from C++ fixed-length byte string, like EdDSA.
     * The all-zero string maps to the identity.
     *
     * @retval DECAF_SUCCESS the string was successfully decoded.
     * @return DECAF_FAILURE the string was the wrong length, or wasn't the encoding of a point.
     * Contents of the point are undefined.
     */
    inline decaf_error_t WARN_UNUSED decode_like_eddsa_noexcept (
        const FixedBlock<$(C_NS)_EDDSA_PUBLIC_BYTES> &buffer
    ) NOEXCEPT {
        return $(c_ns)_point_decode_like_eddsa(p,buffer.data());
    }

    inline void decode_like_eddsa (
        const FixedBlock<$(C_NS)_EDDSA_PUBLIC_BYTES> &buffer
    ) throw(CryptoException) {
        if (DECAF_SUCCESS != decode_like_eddsa_noexcept(buffer)) throw(CryptoException());
    }

    /**
     * Encode like EdDSA.  FIXME: and multiply by the cofactor...
     */
    inline SecureBuffer encode_like_eddsa() const {
        SecureBuffer ret($(C_NS)_EDDSA_PUBLIC_BYTES);
        $(c_ns)_point_encode_like_eddsa(ret.data(),p);
        return ret;
    }

    /**
     * Map uniformly to the curve from a hash buffer.
     * The empty or all-zero string maps to the identity, as does the string "\\x01".
     * If the buffer is shorter than 2*HASH_BYTES, well, it won't be as uniform,
     * but the buffer will be zero-padded on the right.
     */
    static inline Point from_hash ( const Block &s ) NOEXCEPT {
        Point p((NOINIT())); p.set_to_hash(s); return p;
    }

    /**
     * Map to the curve from a hash buffer.
     * The empty or all-zero string maps to the identity, as does the string "\\x01".
     * If the buffer is shorter than 2*HASH_BYTES, well, it won't be as uniform,
     * but the buffer will be zero-padded on the right.
     */
    inline void set_to_hash( const Block &s ) NOEXCEPT {
        if (s.size() < HASH_BYTES) {
            SecureBuffer b(HASH_BYTES);
            memcpy(b.data(), s.data(), s.size());
            $(c_ns)_point_from_hash_nonuniform(p,b.data());
        } else if (s.size() == HASH_BYTES) {
            $(c_ns)_point_from_hash_nonuniform(p,s.data());
        } else if (s.size() < 2*HASH_BYTES) {
            SecureBuffer b(2*HASH_BYTES);
            memcpy(b.data(), s.data(), s.size());
            $(c_ns)_point_from_hash_uniform(p,b.data());
        } else {
            $(c_ns)_point_from_hash_uniform(p,s.data());
        }
    }

    /**
     * Encode to string. The identity encodes to the all-zero string.
     */
    inline operator SecureBuffer() const {
        SecureBuffer buffer(SER_BYTES);
        $(c_ns)_point_encode(buffer.data(), p);
        return buffer;
    }

    /** Serializable instance */
    inline size_t ser_size() const NOEXCEPT { return SER_BYTES; }

    /** Serializable instance */
    inline void serialize_into(unsigned char *buffer) const NOEXCEPT {
        $(c_ns)_point_encode(buffer, p);
    }

    /** Point add. */
    inline Point operator+ (const Point &q) const NOEXCEPT { Point r((NOINIT())); $(c_ns)_point_add(r.p,p,q.p); return r; }

    /** Point add. */
    inline Point &operator+=(const Point &q) NOEXCEPT { $(c_ns)_point_add(p,p,q.p); return *this; }

    /** Point subtract. */
    inline Point operator- (const Point &q) const NOEXCEPT { Point r((NOINIT())); $(c_ns)_point_sub(r.p,p,q.p); return r; }

    /** Point subtract. */
    inline Point &operator-=(const Point &q) NOEXCEPT { $(c_ns)_point_sub(p,p,q.p); return *this; }

    /** Point negate. */
    inline Point operator- () const NOEXCEPT { Point r((NOINIT())); $(c_ns)_point_negate(r.p,p); return r; }

    /** Double the point out of place. */
    inline Point times_two () const NOEXCEPT { Point r((NOINIT())); $(c_ns)_point_double(r.p,p); return r; }

    /** Double the point in place. */
    inline Point &double_in_place() NOEXCEPT { $(c_ns)_point_double(p,p); return *this; }

    /** Constant-time compare. */
    inline bool operator!=(const Point &q) const NOEXCEPT { return ! $(c_ns)_point_eq(p,q.p); }

    /** Constant-time compare. */
    inline bool operator==(const Point &q) const NOEXCEPT { return !!$(c_ns)_point_eq(p,q.p); }

    /** Scalar multiply. */
    inline Point operator* (const Scalar &s) const NOEXCEPT { Point r((NOINIT())); $(c_ns)_point_scalarmul(r.p,p,s.s); return r; }

    /** Scalar multiply in place. */
    inline Point &operator*=(const Scalar &s) NOEXCEPT { $(c_ns)_point_scalarmul(p,p,s.s); return *this; }

    /** Multiply by s.inverse(). If s=0, maps to the identity. */
    inline Point operator/ (const Scalar &s) const throw(CryptoException) { return (*this) * s.inverse(); }

    /** Multiply by s.inverse(). If s=0, maps to the identity. */
    inline Point &operator/=(const Scalar &s) throw(CryptoException) { return (*this) *= s.inverse(); }

    /** Validate / sanity check */
    inline bool validate() const NOEXCEPT { return $(c_ns)_point_valid(p); }

    /** Double-scalar multiply, equivalent to q*qs + r*rs but faster. */
    static inline Point double_scalarmul (
        const Point &q, const Scalar &qs, const Point &r, const Scalar &rs
    ) NOEXCEPT {
        Point p((NOINIT())); $(c_ns)_point_double_scalarmul(p.p,q.p,qs.s,r.p,rs.s); return p;
    }

    /** Dual-scalar multiply, equivalent to this*r1, this*r2 but faster. */
    inline void dual_scalarmul (
        Point &q1, Point &q2, const Scalar &r1, const Scalar &r2
    ) const NOEXCEPT {
        $(c_ns)_point_dual_scalarmul(q1.p,q2.p,p,r1.s,r2.s);
    }

    /**
     * Double-scalar multiply, equivalent to q*qs + r*rs but faster.
     * For those who like their scalars before the point.
     */
    static inline Point double_scalarmul (
        const Scalar &qs, const Point &q, const Scalar &rs, const Point &r
    ) NOEXCEPT {
        return double_scalarmul(q,qs,r,rs);
    }

    /**
     * Double-scalar multiply: this point by the first scalar and base by the second scalar.
     * @warning This function takes variable time, and may leak the scalars (or points, but currently
     * it doesn't).
     */
    inline Point non_secret_combo_with_base(const Scalar &s, const Scalar &s_base) NOEXCEPT {
        Point r((NOINIT())); $(c_ns)_base_double_scalarmul_non_secret(r.p,s_base.s,p,s.s); return r;
    }

    /** Return a point equal to *this, whose internal data is rotated by a torsion element. */
    inline Point debugging_torque() const NOEXCEPT {
        Point q;
        $(c_ns)_point_debugging_torque(q.p,p);
        return q;
    }

    /** Return a point equal to *this, whose internal data has a modified representation. */
    inline Point debugging_pscale(const FixedBlock<SER_BYTES> factor) const NOEXCEPT {
        Point q;
        $(c_ns)_point_debugging_pscale(q.p,p,factor.data());
        return q;
    }

    /** Return a point equal to *this, whose internal data has a randomized representation. */
    inline Point debugging_pscale(Rng &r) const NOEXCEPT {
        FixedArrayBuffer<SER_BYTES> sb(r);
        return debugging_pscale(sb);
    }

    /**
     * Modify buffer so that Point::from_hash(Buffer) == *this, and return DECAF_SUCCESS;
     * or leave buf unmodified and return DECAF_FAILURE.
     */
    inline decaf_error_t invert_elligator (
        Buffer buf, uint32_t hint
    ) const NOEXCEPT {
        unsigned char buf2[2*HASH_BYTES];
        memset(buf2,0,sizeof(buf2));
        memcpy(buf2,buf.data(),(buf.size() > 2*HASH_BYTES) ? 2*HASH_BYTES : buf.size());
        decaf_bool_t ret;
        if (buf.size() > HASH_BYTES) {
            ret = decaf_successful($(c_ns)_invert_elligator_uniform(buf2, p, hint));
        } else {
            ret = decaf_successful($(c_ns)_invert_elligator_nonuniform(buf2, p, hint));
        }
        if (buf.size() < HASH_BYTES) {
            ret &= decaf_memeq(&buf2[buf.size()], &buf2[HASH_BYTES], HASH_BYTES - buf.size());
        }
        for (size_t i=0; i<buf.size() && i<HASH_BYTES; i++) {
            buf[i] = (buf[i] & ~ret) | (buf2[i] &ret);
        }
        decaf_bzero(buf2,sizeof(buf2));
        return decaf_succeed_if(ret);
    }

    /** Steganographically encode this */
    inline SecureBuffer steg_encode(Rng &rng, size_t size=STEG_BYTES) const throw(std::bad_alloc, LengthException) {
        if (size <= HASH_BYTES + 4 || size > 2*HASH_BYTES) throw LengthException();
        SecureBuffer out(STEG_BYTES);
        decaf_error_t done;
        do {
            rng.read(Buffer(out).slice(HASH_BYTES-4,STEG_BYTES-HASH_BYTES+1));
            uint32_t hint = 0;
            for (int i=0; i<4; i++) { hint |= uint32_t(out[HASH_BYTES-4+i])<<(8*i); }
            done = invert_elligator(out, hint);
        } while (!decaf_successful(done));
        return out;
    }

    /** Return the base point */
    static inline const Point base() NOEXCEPT { return Point($(c_ns)_point_base); }

    /** Return the identity point */
    static inline const Point identity() NOEXCEPT { return Point($(c_ns)_point_identity); }
};

/**
 * Precomputed table of points.
 * Minor difficulties arise here because the decaf API doesn't expose, as a constant, how big such an object is.
 * Therefore we have to call malloc() or friends, but that's probably for the best, because you don't want to
 * stack-allocate a 15kiB object anyway.
 */

/** @cond internal */
typedef $(c_ns)_precomputed_s Precomputed_U;
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
     * Initialize from underlying type, declared as a reference to prevent
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
        const Precomputed_U &yours = *default_value()
    ) NOEXCEPT : OwnedOrUnowned<Precomputed,Precomputed_U>(yours) {}


#if __cplusplus >= 201103L
    /** Move-assign operator */
    inline Precomputed &operator=(Precomputed &&it) NOEXCEPT {
        OwnedOrUnowned<Precomputed,Precomputed_U>::operator= (it);
        return *this;
    }

    /** Move constructor */
    inline Precomputed(Precomputed &&it) NOEXCEPT : OwnedOrUnowned<Precomputed,Precomputed_U>() {
        *this = it;
    }

    /** Undelete copy operator */
    inline Precomputed &operator=(const Precomputed &it) NOEXCEPT {
        OwnedOrUnowned<Precomputed,Precomputed_U>::operator= (it);
        return *this;
    }
#endif

    /**
     * Initilaize from point. Must allocate memory, and may throw.
     */
    inline Precomputed &operator=(const Point &it) throw(std::bad_alloc) {
        alloc();
        $(c_ns)_precompute(ours.mine,it.p);
        return *this;
    }

    /**
     * Copy constructor.
     */
    inline Precomputed(const Precomputed &it) throw(std::bad_alloc)
        : OwnedOrUnowned<Precomputed,Precomputed_U>() { *this = it; }

    /**
     * Constructor which initializes from point.
     */
    inline explicit Precomputed(const Point &it) throw(std::bad_alloc)
        : OwnedOrUnowned<Precomputed,Precomputed_U>() { *this = it; }

    /** Fixed base scalarmul. */
    inline Point operator* (const Scalar &s) const NOEXCEPT { Point r; $(c_ns)_precomputed_scalarmul(r.p,get(),s.s); return r; }

    /** Multiply by s.inverse(). If s=0, maps to the identity. */
    inline Point operator/ (const Scalar &s) const throw(CryptoException) { return (*this) * s.inverse(); }

    /** Return the table for the base point. */
    static inline const Precomputed base() NOEXCEPT { return Precomputed(); }

public:
    /** @cond internal */
    friend class OwnedOrUnowned<Precomputed,Precomputed_U>;
    static inline size_t size() NOEXCEPT { return $(c_ns)_sizeof_precomputed_s; }
    static inline size_t alignment() NOEXCEPT { return $(c_ns)_alignof_precomputed_s; }
    static inline const Precomputed_U * default_value() NOEXCEPT { return $(c_ns)_precomputed_base; }
    /** @endcond */
};

struct DhLadder {
public:
    /** Bytes in an X$(gf_shortname) public key. */
    static const size_t PUBLIC_BYTES = X$(gf_shortname)_PUBLIC_BYTES;

    /** Bytes in an X$(gf_shortname) private key. */
    static const size_t PRIVATE_BYTES = X$(gf_shortname)_PRIVATE_BYTES;

    /** Base point for a scalar multiplication. */
    static const FixedBlock<PUBLIC_BYTES> base_point() NOEXCEPT {
        return FixedBlock<PUBLIC_BYTES>($(c_ns)_x_base_point);
    }

    /** Generate and return a shared secret with public key.  */
    static inline SecureBuffer shared_secret(
        const FixedBlock<PUBLIC_BYTES> &pk,
        const FixedBlock<PRIVATE_BYTES> &scalar
    ) throw(std::bad_alloc,CryptoException) {
        SecureBuffer out(PUBLIC_BYTES);
        if (DECAF_SUCCESS != decaf_x$(gf_shortname)_direct_scalarmul(out.data(), pk.data(), scalar.data())) {
            throw CryptoException();
        }
        return out;
    }

    /** Generate and return a shared secret with public key, noexcept version.  */
    static inline decaf_error_t WARN_UNUSED
    shared_secret_noexcept (
        FixedBuffer<PUBLIC_BYTES> &out,
        const FixedBlock<PUBLIC_BYTES> &pk,
        const FixedBlock<PRIVATE_BYTES> &scalar
    ) NOEXCEPT {
       return decaf_x$(gf_shortname)_direct_scalarmul(out.data(), pk.data(), scalar.data());
    }

    /** Generate and return a public key; equivalent to shared_secret(base_point(),scalar)
     * but possibly faster.
     */
    static inline SecureBuffer generate_key(
        const FixedBlock<PRIVATE_BYTES> &scalar
    ) throw(std::bad_alloc) {
        SecureBuffer out(PUBLIC_BYTES);
        decaf_x$(gf_shortname)_base_scalarmul(out.data(), scalar.data());
        return out;
    }

    /** Generate and return a public key into a fixed buffer;
     * equivalent to shared_secret(base_point(),scalar) but possibly faster.
     */
    static inline void
    generate_key_noexcept (
        FixedBuffer<PUBLIC_BYTES> &out,
        const FixedBlock<PRIVATE_BYTES> &scalar
    ) NOEXCEPT {
        decaf_x$(gf_shortname)_base_scalarmul(out.data(), scalar.data());
    }
};

}; /* struct $(cxx_ns) */

/** @cond internal */
inline SecureBuffer $(cxx_ns)::Scalar::direct_scalarmul (
    const Block &in,
    decaf_bool_t allow_identity,
    decaf_bool_t short_circuit
) const throw(CryptoException) {
    SecureBuffer out($(cxx_ns)::Point::SER_BYTES);
    if (DECAF_SUCCESS !=
        $(c_ns)_direct_scalarmul(out.data(), in.data(), s, allow_identity, short_circuit)
    ) {
        throw CryptoException();
    }
    return out;
}
/** @endcond */

#undef NOEXCEPT
} /* namespace decaf */
