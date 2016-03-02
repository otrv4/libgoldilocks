/** @brief A group of prime order p, based on $(iso_to). */

#include <decaf/common.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond internal */
#define $(C_NS)_SCALAR_LIMBS (($(scalar_bits)-1)/DECAF_WORD_BITS+1)
/** @endcond */

/** The number of bits in a scalar */
#define $(C_NS)_SCALAR_BITS $(scalar_bits)

/** @cond internal */
#ifndef __DECAF_$(gf_shortname)_GF_DEFINED__
#define __DECAF_$(gf_shortname)_GF_DEFINED__ 1
/** @brief Galois field element internal structure */
typedef struct gf_$(gf_shortname)_s {
    decaf_word_t limb[$(gf_impl_bits)/DECAF_WORD_BITS];
} __attribute__((aligned(32))) gf_$(gf_shortname)_s, gf_$(gf_shortname)_t[1];
#endif /* __DECAF_$(gf_shortname)_GF_DEFINED__ */
/** @endcond */

/** Number of bytes in a serialized point. */
#define $(C_NS)_SER_BYTES $((gf_bits-2)/8 + 1)

/** Number of bytes in an elligated point.  For now set the same as SER_BYTES
 * but could be different for other curves.
 */
#define $(C_NS)_HASH_BYTES $((gf_bits-2)/8 + 1)

/** Number of bytes in a serialized scalar. */
#define $(C_NS)_SCALAR_BYTES $((scalar_bits-1)/8 + 1)

/** Number of bits in the "which" field of an elligator inverse */
#define $(C_NS)_INVERT_ELLIGATOR_WHICH_BITS $(ceil_log2(cofactor) + 7 + elligator_onto - ((gf_bits-2) % 8))

/** Number of bytes in an x$(gf_shortname) public key */
#define X$(gf_shortname)_PUBLIC_BYTES $((gf_bits-1)/8 + 1)

/** Number of bytes in an x$(gf_shortname) private key */
#define X$(gf_shortname)_PRIVATE_BYTES $((gf_bits-1)/8 + 1)

/** Twisted Edwards extended homogeneous coordinates */
typedef struct $(c_ns)_point_s {
    /** @cond internal */
    gf_$(gf_shortname)_t x,y,z,t;
    /** @endcond */
} $(c_ns)_point_t[1];

/** Precomputed table based on a point.  Can be trivial implementation. */
struct $(c_ns)_precomputed_s;

/** Precomputed table based on a point.  Can be trivial implementation. */
typedef struct $(c_ns)_precomputed_s $(c_ns)_precomputed_s; 

/** Size and alignment of precomputed point tables. */
extern const size_t $(c_ns)_sizeof_precomputed_s API_VIS, $(c_ns)_alignof_precomputed_s API_VIS;

/** Scalar is stored packed, because we don't need the speed. */
typedef struct $(c_ns)_scalar_s {
    /** @cond internal */
    decaf_word_t limb[$(C_NS)_SCALAR_LIMBS];
    /** @endcond */
} $(c_ns)_scalar_t[1];

/** A scalar equal to 1. */
extern const $(c_ns)_scalar_t $(c_ns)_scalar_one API_VIS;

/** A scalar equal to 0. */
extern const $(c_ns)_scalar_t $(c_ns)_scalar_zero API_VIS;

/** The identity point on the curve. */
extern const $(c_ns)_point_t $(c_ns)_point_identity API_VIS;

/** An arbitrarily chosen base point on the curve.
 * @warning TODO: this is subject to change.  It is currently
 * the preimage of the X$(gf_shortname) base point.  Sometime
 * soon, we will merge and finalize support for X$(gf_shortname)
 * and Ed$(gf_shortname) integration.  This might make some
 * multiple of the current basepoint (eg twice it, or the cofactor
 * times it) more convenient API-wise, and trigger a changeover.
 */
extern const $(c_ns)_point_t $(c_ns)_point_base API_VIS;

/** Precomputed table for the base point on the curve. */
extern const struct $(c_ns)_precomputed_s *$(c_ns)_precomputed_base API_VIS;

/**
 * @brief Read a scalar from wire format or from bytes.
 *
 * @param [in] ser Serialized form of a scalar.
 * @param [out] out Deserialized form.
 *
 * @retval DECAF_SUCCESS The scalar was correctly encoded.
 * @retval DECAF_FAILURE The scalar was greater than the modulus,
 * and has been reduced modulo that modulus.
 */
decaf_error_t $(c_ns)_scalar_decode (
    $(c_ns)_scalar_t out,
    const unsigned char ser[$(C_NS)_SCALAR_BYTES]
) API_VIS WARN_UNUSED NONNULL NOINLINE;

/**
 * @brief Read a scalar from wire format or from bytes.  Reduces mod
 * scalar prime.
 *
 * @param [in] ser Serialized form of a scalar.
 * @param [in] ser_len Length of serialized form.
 * @param [out] out Deserialized form.
 */
void $(c_ns)_scalar_decode_long (
    $(c_ns)_scalar_t out,
    const unsigned char *ser,
    size_t ser_len
) API_VIS NONNULL NOINLINE;
    
/**
 * @brief Serialize a scalar to wire format.
 *
 * @param [out] ser Serialized form of a scalar.
 * @param [in] s Deserialized scalar.
 */
void $(c_ns)_scalar_encode (
    unsigned char ser[$(C_NS)_SCALAR_BYTES],
    const $(c_ns)_scalar_t s
) API_VIS NONNULL NOINLINE NOINLINE;
        
/**
 * @brief Add two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a+b.
 */
void $(c_ns)_scalar_add (
    $(c_ns)_scalar_t out,
    const $(c_ns)_scalar_t a,
    const $(c_ns)_scalar_t b
) API_VIS NONNULL NOINLINE;

/**
 * @brief Compare two scalars.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @retval DECAF_TRUE The scalars are equal.
 * @retval DECAF_FALSE The scalars are not equal.
 */    
decaf_bool_t $(c_ns)_scalar_eq (
    const $(c_ns)_scalar_t a,
    const $(c_ns)_scalar_t b
) API_VIS WARN_UNUSED NONNULL NOINLINE;

/**
 * @brief Subtract two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a-b.
 */  
void $(c_ns)_scalar_sub (
    $(c_ns)_scalar_t out,
    const $(c_ns)_scalar_t a,
    const $(c_ns)_scalar_t b
) API_VIS NONNULL NOINLINE;

/**
 * @brief Multiply two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a*b.
 */  
void $(c_ns)_scalar_mul (
    $(c_ns)_scalar_t out,
    const $(c_ns)_scalar_t a,
    const $(c_ns)_scalar_t b
) API_VIS NONNULL NOINLINE;
        
/**
* @brief Halve a scalar.  The scalars may use the same memory.
* @param [in] a A scalar.
* @param [out] out a/2.
*/
void $(c_ns)_scalar_halve (
   $(c_ns)_scalar_t out,
   const $(c_ns)_scalar_t a
) API_VIS NONNULL NOINLINE;

/**
 * @brief Invert a scalar.  When passed zero, return 0.  The input and output may alias.
 * @param [in] a A scalar.
 * @param [out] out 1/a.
 * @return DECAF_SUCCESS The input is nonzero.
 */  
decaf_error_t $(c_ns)_scalar_invert (
    $(c_ns)_scalar_t out,
    const $(c_ns)_scalar_t a
) API_VIS WARN_UNUSED NONNULL NOINLINE;

/**
 * @brief Copy a scalar.  The scalars may use the same memory, in which
 * case this function does nothing.
 * @param [in] a A scalar.
 * @param [out] out Will become a copy of a.
 */
static inline void NONNULL $(c_ns)_scalar_copy (
    $(c_ns)_scalar_t out,
    const $(c_ns)_scalar_t a
) {
    *out = *a;
}

/**
 * @brief Set a scalar to an unsigned 64-bit integer.
 * @param [in] a An integer.
 * @param [out] out Will become equal to a.
 */  
void $(c_ns)_scalar_set_unsigned (
    $(c_ns)_scalar_t out,
    uint64_t a
) API_VIS NONNULL;

/**
 * @brief Encode a point as a sequence of bytes.
 *
 * @param [out] ser The byte representation of the point.
 * @param [in] pt The point to encode.
 */
void $(c_ns)_point_encode (
    uint8_t ser[$(C_NS)_SER_BYTES],
    const $(c_ns)_point_t pt
) API_VIS NONNULL NOINLINE;

/**
 * @brief Decode a point from a sequence of bytes.
 *
 * Every point has a unique encoding, so not every
 * sequence of bytes is a valid encoding.  If an invalid
 * encoding is given, the output is undefined.
 *
 * @param [out] pt The decoded point.
 * @param [in] ser The serialized version of the point.
 * @param [in] allow_identity DECAF_TRUE if the identity is a legal input.
 * @retval DECAF_SUCCESS The decoding succeeded.
 * @retval DECAF_FAILURE The decoding didn't succeed, because
 * ser does not represent a point.
 */
decaf_error_t $(c_ns)_point_decode (
    $(c_ns)_point_t pt,
    const uint8_t ser[$(C_NS)_SER_BYTES],
    decaf_bool_t allow_identity
) API_VIS WARN_UNUSED NONNULL NOINLINE;

/**
 * @brief Copy a point.  The input and output may alias,
 * in which case this function does nothing.
 *
 * @param [out] a A copy of the point.
 * @param [in] b Any point.
 */
static inline void NONNULL $(c_ns)_point_copy (
    $(c_ns)_point_t a,
    const $(c_ns)_point_t b
) {
    *a=*b;
}

/**
 * @brief Test whether two points are equal.  If yes, return
 * DECAF_TRUE, else return DECAF_FALSE.
 *
 * @param [in] a A point.
 * @param [in] b Another point.
 * @retval DECAF_TRUE The points are equal.
 * @retval DECAF_FALSE The points are not equal.
 */
decaf_bool_t $(c_ns)_point_eq (
    const $(c_ns)_point_t a,
    const $(c_ns)_point_t b
) API_VIS WARN_UNUSED NONNULL NOINLINE;

/**
 * @brief Add two points to produce a third point.  The
 * input points and output point can be pointers to the same
 * memory.
 *
 * @param [out] sum The sum a+b.
 * @param [in] a An addend.
 * @param [in] b An addend.
 */
void $(c_ns)_point_add (
    $(c_ns)_point_t sum,
    const $(c_ns)_point_t a,
    const $(c_ns)_point_t b
) API_VIS NONNULL;

/**
 * @brief Double a point.  Equivalent to
 * $(c_ns)_point_add(two_a,a,a), but potentially faster.
 *
 * @param [out] two_a The sum a+a.
 * @param [in] a A point.
 */
void $(c_ns)_point_double (
    $(c_ns)_point_t two_a,
    const $(c_ns)_point_t a
) API_VIS NONNULL;

/**
 * @brief Subtract two points to produce a third point.  The
 * input points and output point can be pointers to the same
 * memory.
 *
 * @param [out] diff The difference a-b.
 * @param [in] a The minuend.
 * @param [in] b The subtrahend.
 */
void $(c_ns)_point_sub (
    $(c_ns)_point_t diff,
    const $(c_ns)_point_t a,
    const $(c_ns)_point_t b
) API_VIS NONNULL;
    
/**
 * @brief Negate a point to produce another point.  The input
 * and output points can use the same memory.
 *
 * @param [out] nega The negated input point
 * @param [in] a The input point.
 */
void $(c_ns)_point_negate (
   $(c_ns)_point_t nega,
   const $(c_ns)_point_t a
) API_VIS NONNULL;

/**
 * @brief Multiply a base point by a scalar: scaled = scalar*base.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multiply by.
 */
void $(c_ns)_point_scalarmul (
    $(c_ns)_point_t scaled,
    const $(c_ns)_point_t base,
    const $(c_ns)_scalar_t scalar
) API_VIS NONNULL NOINLINE;

/**
 * @brief Multiply a base point by a scalar: scaled = scalar*base.
 * This function operates directly on serialized forms.
 *
 * @warning This function is experimental.  It may not be supported
 * long-term.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multiply by.
 * @param [in] allow_identity Allow the input to be the identity.
 * @param [in] short_circuit Allow a fast return if the input is illegal.
 *
 * @retval DECAF_SUCCESS The scalarmul succeeded.
 * @retval DECAF_FAILURE The scalarmul didn't succeed, because
 * base does not represent a point.
 */
decaf_error_t $(c_ns)_direct_scalarmul (
    uint8_t scaled[$(C_NS)_SER_BYTES],
    const uint8_t base[$(C_NS)_SER_BYTES],
    const $(c_ns)_scalar_t scalar,
    decaf_bool_t allow_identity,
    decaf_bool_t short_circuit
) API_VIS NONNULL WARN_UNUSED NOINLINE;

/**
 * @brief RFC 7748 Diffie-Hellman scalarmul.  This function uses a different
 * (non-Decaf) encoding.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multiply by.
 *
 * @retval DECAF_SUCCESS The scalarmul succeeded.
 * @retval DECAF_FAILURE The scalarmul didn't succeed, because the base
 * point is in a small subgroup.
 */
decaf_error_t decaf_x$(gf_shortname)_direct_scalarmul (
    uint8_t out[X$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t base[X$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t scalar[X$(gf_shortname)_PRIVATE_BYTES]
) API_VIS NONNULL WARN_UNUSED NOINLINE;

/** The base point for X$(gf_shortname) Diffie-Hellman */
extern const uint8_t $(c_ns)_x_base_point[X$(gf_shortname)_PUBLIC_BYTES] API_VIS;

/**
 * @brief RFC 7748 Diffie-Hellman base point scalarmul.  This function uses
 * a different (non-Decaf) encoding.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] scalar The scalar to multiply by.
 */
void decaf_x$(gf_shortname)_base_scalarmul (
    uint8_t out[X$(gf_shortname)_PUBLIC_BYTES],
    const uint8_t scalar[X$(gf_shortname)_PRIVATE_BYTES]
) API_VIS NONNULL NOINLINE;

/* FUTURE: uint8_t $(c_ns)_encode_like_curve$(gf_shortname)) */

/**
 * @brief Precompute a table for fast scalar multiplication.
 * Some implementations do not include precomputed points; for
 * those implementations, this implementation simply copies the
 * point.
 *
 * @param [out] a A precomputed table of multiples of the point.
 * @param [in] b Any point.
 */
void $(c_ns)_precompute (
    $(c_ns)_precomputed_s *a,
    const $(c_ns)_point_t b
) API_VIS NONNULL NOINLINE;

/**
 * @brief Multiply a precomputed base point by a scalar:
 * scaled = scalar*base.
 * Some implementations do not include precomputed points; for
 * those implementations, this function is the same as
 * $(c_ns)_point_scalarmul
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multiply by.
 */
void $(c_ns)_precomputed_scalarmul (
    $(c_ns)_point_t scaled,
    const $(c_ns)_precomputed_s *base,
    const $(c_ns)_scalar_t scalar
) API_VIS NONNULL NOINLINE;

/**
 * @brief Multiply two base points by two scalars:
 * scaled = scalar1*base1 + scalar2*base2.
 *
 * Equivalent to two calls to $(c_ns)_point_scalarmul, but may be
 * faster.
 *
 * @param [out] combo The linear combination scalar1*base1 + scalar2*base2.
 * @param [in] base1 A first point to be scaled.
 * @param [in] scalar1 A first scalar to multiply by.
 * @param [in] base2 A second point to be scaled.
 * @param [in] scalar2 A second scalar to multiply by.
 */
void $(c_ns)_point_double_scalarmul (
    $(c_ns)_point_t combo,
    const $(c_ns)_point_t base1,
    const $(c_ns)_scalar_t scalar1,
    const $(c_ns)_point_t base2,
    const $(c_ns)_scalar_t scalar2
) API_VIS NONNULL NOINLINE;
    
/**
 * Multiply one base point by two scalars:
 *
 * a1 = scalar1 * base
 * a2 = scalar2 * base
 *
 * Equivalent to two calls to $(c_ns)_point_scalarmul, but may be
 * faster.
 *
 * @param [out] a1 The first multiple.  It may be the same as the input point.
 * @param [out] a2 The second multiple.  It may be the same as the input point.
 * @param [in] base1 A point to be scaled.
 * @param [in] scalar1 A first scalar to multiply by.
 * @param [in] scalar2 A second scalar to multiply by.
 */
void $(c_ns)_point_dual_scalarmul (
    $(c_ns)_point_t a1,
    $(c_ns)_point_t a2,
    const $(c_ns)_point_t base1,
    const $(c_ns)_scalar_t scalar1,
    const $(c_ns)_scalar_t scalar2
) API_VIS NONNULL NOINLINE;

/**
 * @brief Multiply two base points by two scalars:
 * scaled = scalar1*$(c_ns)_point_base + scalar2*base2.
 *
 * Otherwise equivalent to $(c_ns)_point_double_scalarmul, but may be
 * faster at the expense of being variable time.
 *
 * @param [out] combo The linear combination scalar1*base + scalar2*base2.
 * @param [in] scalar1 A first scalar to multiply by.
 * @param [in] base2 A second point to be scaled.
 * @param [in] scalar2 A second scalar to multiply by.
 *
 * @warning: This function takes variable time, and may leak the scalars
 * used.  It is designed for signature verification.
 */
void $(c_ns)_base_double_scalarmul_non_secret (
    $(c_ns)_point_t combo,
    const $(c_ns)_scalar_t scalar1,
    const $(c_ns)_point_t base2,
    const $(c_ns)_scalar_t scalar2
) API_VIS NONNULL NOINLINE;

/**
 * @brief Constant-time decision between two points.  If pick_b
 * is zero, out = a; else out = b.
 *
 * @param [out] out The output.  It may be the same as either input.
 * @param [in] a Any point.
 * @param [in] b Any point.
 * @param [in] pick_b If nonzero, choose point b.
 */
void $(c_ns)_point_cond_sel (
    $(c_ns)_point_t out,
    const $(c_ns)_point_t a,
    const $(c_ns)_point_t b,
    decaf_word_t pick_b
) API_VIS NONNULL NOINLINE;

/**
 * @brief Constant-time decision between two scalars.  If pick_b
 * is zero, out = a; else out = b.
 *
 * @param [out] out The output.  It may be the same as either input.
 * @param [in] a Any scalar.
 * @param [in] b Any scalar.
 * @param [in] pick_b If nonzero, choose scalar b.
 */
void $(c_ns)_scalar_cond_sel (
    $(c_ns)_scalar_t out,
    const $(c_ns)_scalar_t a,
    const $(c_ns)_scalar_t b,
    decaf_word_t pick_b
) API_VIS NONNULL NOINLINE;

/**
 * @brief Test that a point is valid, for debugging purposes.
 *
 * @param [in] to_test The point to test.
 * @retval DECAF_TRUE The point is valid.
 * @retval DECAF_FALSE The point is invalid.
 */
decaf_bool_t $(c_ns)_point_valid (
    const $(c_ns)_point_t to_test
) API_VIS WARN_UNUSED NONNULL NOINLINE;

/**
 * @brief Torque a point, for debugging purposes.  The output
 * will be equal to the input.
 *
 * @param [out] q The point to torque.
 * @param [in] p The point to torque.
 */
void $(c_ns)_point_debugging_torque (
    $(c_ns)_point_t q,
    const $(c_ns)_point_t p
) API_VIS NONNULL NOINLINE;

/**
 * @brief Projectively scale a point, for debugging purposes.
 * The output will be equal to the input, and will be valid
 * even if the factor is zero.
 *
 * @param [out] q The point to scale.
 * @param [in] p The point to scale.
 * @param [in] factor Serialized GF factor to scale.
 */
void $(c_ns)_point_debugging_pscale (
    $(c_ns)_point_t q,
    const $(c_ns)_point_t p,
    const unsigned char factor[$(C_NS)_SER_BYTES]
) API_VIS NONNULL NOINLINE;

/**
 * @brief Almost-Elligator-like hash to curve.
 *
 * Call this function with the output of a hash to make a hash to the curve.
 *
 * This function runs Elligator2 on the $(c_ns) Jacobi quartic model.  It then
 * uses the isogeny to put the result in twisted Edwards form.  As a result,
 * it is safe (cannot produce points of order 4), and would be compatible with
 * hypothetical other implementations of Decaf using a Montgomery or untwisted
 * Edwards model.
 *
 * Unlike Elligator, this function may be up to 4:1 on [0,(p-1)/2]:
 *   A factor of 2 due to the isogeny.
 *   A factor of 2 because we quotient out the 2-torsion.
 *
 * This makes it about 8:1 overall, or 16:1 overall on curves with cofactor 8.
 *
 * Negating the input (mod q) results in the same point.  Inverting the input
 * (mod q) results in the negative point.  This is the same as Elligator.
 *
 * This function isn't quite indifferentiable from a random oracle.
 * However, it is suitable for many protocols, including SPEKE and SPAKE2 EE. 
 * Furthermore, calling it twice with independent seeds and adding the results
 * is indifferentiable from a random oracle.
 *
 * @param [in] hashed_data Output of some hash function.
 * @param [out] pt The data hashed to the curve.
 */
void
$(c_ns)_point_from_hash_nonuniform (
    $(c_ns)_point_t pt,
    const unsigned char hashed_data[$(C_NS)_HASH_BYTES]
) API_VIS NONNULL NOINLINE;

/**
 * @brief Indifferentiable hash function encoding to curve.
 *
 * Equivalent to calling $(c_ns)_point_from_hash_nonuniform twice and adding.
 *
 * @param [in] hashed_data Output of some hash function.
 * @param [out] pt The data hashed to the curve.
 */ 
void $(c_ns)_point_from_hash_uniform (
    $(c_ns)_point_t pt,
    const unsigned char hashed_data[2*$(C_NS)_HASH_BYTES]
) API_VIS NONNULL NOINLINE;

/**
 * @brief Inverse of elligator-like hash to curve.
 *
 * This function writes to the buffer, to make it so that
 * $(c_ns)_point_from_hash_nonuniform(buffer) = pt if
 * possible.  Since there may be multiple preimages, the
 * "which" parameter chooses between them.  To ensure uniform
 * inverse sampling, this function succeeds or fails
 * independently for different "which" values.
 *
 * @param [out] recovered_hash Encoded data.
 * @param [in] pt The point to encode.
 * @param [in] which A value determining which inverse point
 * to return.
 *
 * @retval DECAF_SUCCESS The inverse succeeded.
 * @retval DECAF_FAILURE The inverse failed.
 */
decaf_error_t
$(c_ns)_invert_elligator_nonuniform (
    unsigned char recovered_hash[$(C_NS)_HASH_BYTES],
    const $(c_ns)_point_t pt,
    uint32_t which
) API_VIS NONNULL NOINLINE WARN_UNUSED;

/**
 * @brief Inverse of elligator-like hash to curve.
 *
 * This function writes to the buffer, to make it so that
 * $(c_ns)_point_from_hash_uniform(buffer) = pt if
 * possible.  Since there may be multiple preimages, the
 * "which" parameter chooses between them.  To ensure uniform
 * inverse sampling, this function succeeds or fails
 * independently for different "which" values.
 *
 * @param [out] recovered_hash Encoded data.
 * @param [in] pt The point to encode.
 * @param [in] which A value determining which inverse point
 * to return.
 *
 * @retval DECAF_SUCCESS The inverse succeeded.
 * @retval DECAF_FAILURE The inverse failed.
 */
decaf_error_t
$(c_ns)_invert_elligator_uniform (
    unsigned char recovered_hash[2*$(C_NS)_HASH_BYTES],
    const $(c_ns)_point_t pt,
    uint32_t which
) API_VIS NONNULL NOINLINE WARN_UNUSED;

/**
 * @brief Overwrite scalar with zeros.
 */
void $(c_ns)_scalar_destroy (
    $(c_ns)_scalar_t scalar
) NONNULL API_VIS;

/**
 * @brief Overwrite point with zeros.
 */
void $(c_ns)_point_destroy (
    $(c_ns)_point_t point
) NONNULL API_VIS;

/**
 * @brief Overwrite precomputed table with zeros.
 */
void $(c_ns)_precomputed_destroy (
    $(c_ns)_precomputed_s *pre
) NONNULL API_VIS;

#ifdef __cplusplus
} /* extern "C" */
#endif
