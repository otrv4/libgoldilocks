/** @brief Elligator high-level functions. */

#include "word.h"
#include "field.h"
#include <decaf.h>

/* Template stuff */
#define API_NS(_id) $(c_ns)_##_id
#define point_t API_NS(point_t)
#define IMAGINE_TWIST $(imagine_twist)
#define COFACTOR $(cofactor)
static const int EDWARDS_D = $(d);
/* End of template stuff */

extern void API_NS(deisogenize) (
    gf_s *__restrict__ s,
    gf_s *__restrict__ minus_t_over_s,
    const point_t p,
    mask_t toggle_hibit_s,
    mask_t toggle_hibit_t_over_s,
    mask_t toggle_rotation
);

void API_NS(point_from_hash_nonuniform) (
    point_t p,
    const unsigned char ser[SER_BYTES]
) {
    gf r0,r,a,b,c,N,e;
    ignore_result(gf_deserialize(r0,ser,0));
    gf_strong_reduce(r0);
    gf_sqr(a,r0);
    gf_mul_qnr(r,a);

    /* Compute D@c := (dr+a-d)(dr-ar-d) with a=1 */
    gf_sub(a,r,ONE);
    gf_mulw(b,a,EDWARDS_D); /* dr-d */
    gf_add(a,b,ONE);
    gf_sub(b,b,r);
    gf_mul(c,a,b);
    
    /* compute N := (r+1)(a-2d) */
    gf_add(a,r,ONE);
    gf_mulw(N,a,1-2*EDWARDS_D);
    
    /* e = +-sqrt(1/ND) or +-r0 * sqrt(qnr/ND) */
    gf_mul(a,c,N);
    mask_t square = gf_isr(b,a);
    gf_cond_sel(c,r0,ONE,square); /* r? = square ? 1 : r0 */
    gf_mul(e,b,c);
    
    /* s@a = +-|N.e| */
    gf_mul(a,N,e);
    gf_cond_neg(a,gf_hibit(a)^square); /* NB this is - what is listed in the paper */
    
    /* t@b = -+ cN(r-1)((a-2d)e)^2 - 1 */
    gf_mulw(c,e,1-2*EDWARDS_D); /* (a-2d)e */
    gf_sqr(b,c);
    gf_sub(e,r,ONE);
    gf_mul(c,b,e);
    gf_mul(b,c,N);
    gf_cond_neg(b,square);
    gf_sub(b,b,ONE);

    /* isogenize */
#if IMAGINE_TWIST
    gf_mul(c,a,SQRT_MINUS_ONE);
    gf_copy(a,c);
#endif
    
    gf_sqr(c,a); /* s^2 */
    gf_add(a,a,a); /* 2s */
    gf_add(e,c,ONE);
    gf_mul(p->t,a,e); /* 2s(1+s^2) */
    gf_mul(p->x,a,b); /* 2st */
    gf_sub(a,ONE,c);
    gf_mul(p->y,e,a); /* (1+s^2)(1-s^2) */
    gf_mul(p->z,a,b); /* (1-s^2)t */
    
    assert(API_NS(point_valid)(p));
}

void API_NS(point_from_hash_uniform) (
    point_t pt,
    const unsigned char hashed_data[2*SER_BYTES]
) {
    point_t pt2;
    API_NS(point_from_hash_nonuniform)(pt,hashed_data);
    API_NS(point_from_hash_nonuniform)(pt2,&hashed_data[SER_BYTES]);
    API_NS(point_add)(pt,pt,pt2);
}

/* Elligator_onto:
 * Make elligator-inverse onto at the cost of roughly halving the success probability.
 * Currently no effect for curves with field size 1 bit mod 8 (where the top bit
 * is chopped off).  FUTURE MAGIC: automatic at least for brainpool-style curves; support
 * log p == 1 mod 8 brainpool curves maybe?
 */
#define MAX(A,B) (((A)>(B)) ? (A) : (B))
#define PKP_MASK ((1<<(MAX(8*SER_BYTES + $(elligator_onto) - $(gf_bits),0)))-1)
#if PKP_MASK != 0
static DECAF_INLINE mask_t plus_k_p (
    uint8_t x[SER_BYTES],
    uint32_t factor_
) {
    uint32_t carry = 0;
    uint64_t factor = factor_;
    const uint8_t p[SER_BYTES] = { $(ser(modulus,8)) };
    for (unsigned int i=0; i<SER_BYTES; i++) {
        uint64_t tmp = carry + p[i] * factor + x[i];
        /* tmp <= 2^32-1 + (2^32-1)*(2^8-1) + (2^8-1) = 2^40-1 */
        x[i] = tmp; carry = tmp>>8;
    }
    return word_is_zero(carry);
}
#endif

decaf_error_t
API_NS(invert_elligator_nonuniform) (
    unsigned char recovered_hash[SER_BYTES],
    const point_t p,
    uint32_t hint_
) {
    mask_t hint = hint_;
    mask_t sgn_s = -(hint & 1),
        sgn_t_over_s = -(hint>>1 & 1),
        sgn_r0 = -(hint>>2 & 1),
        /* FUTURE MAGIC: eventually if there's a curve which needs sgn_ed_T but not sgn_r0,
         * change this mask extraction.
         */
        sgn_ed_T = -(hint>>3 & 1);
    gf a, b, c, d;
    API_NS(deisogenize)(a,c,p,sgn_s,sgn_t_over_s,sgn_ed_T);
    
#if $(gf_bits) == 8*SER_BYTES + 1 /* p521. */
    sgn_r0 = 0;
#endif
    
    /* ok, a = s; c = -t/s */
    gf_mul(b,c,a);
    gf_sub(b,ONE,b); /* t+1 */
    gf_sqr(c,a); /* s^2 */
    mask_t is_identity = gf_eq(p->t,ZERO);

    /* identity adjustments */
    /* in case of identity, currently c=0, t=0, b=1, will encode to 1 */
    /* if hint is 0, -> 0 */
    /* if hint is to neg t/s, then go to infinity, effectively set s to 1 */
    gf_cond_sel(c,c,ONE,is_identity & sgn_t_over_s);
    gf_cond_sel(b,b,ZERO,is_identity & ~sgn_t_over_s & ~sgn_s);
        
    gf_mulw(d,c,2*EDWARDS_D-1); /* $d = (2d-a)s^2 */
    gf_add(a,b,d); /* num? */
    gf_sub(d,d,b); /* den? */
    gf_mul(b,a,d); /* n*d */
    gf_cond_sel(a,d,a,sgn_s);
    gf_mul_qnr(d,b);
    mask_t succ = gf_isr(c,d)|gf_eq(d,ZERO);
    gf_mul(b,a,c);
    gf_cond_neg(b, sgn_r0^gf_hibit(b));
    
    succ &= ~(gf_eq(b,ZERO) & sgn_r0);
    #if COFACTOR == 8
        succ &= ~(is_identity & sgn_ed_T); /* NB: there are no preimages of rotated identity. */
    #endif
    
    #if $(gf_bits) == 8*SER_BYTES + 1 /* p521 */
        gf_serialize(recovered_hash,b,0);
    #else
        gf_serialize(recovered_hash,b,1);
        #if PKP_MASK != 0
            /* Add a multiple of p to make the result either almost-onto or completely onto. */
            #if COFACTOR == 8
                succ &= plus_k_p(recovered_hash, (hint >> 4) & PKP_MASK);
            #else
                succ &= plus_k_p(recovered_hash, (hint >> 3) & PKP_MASK);
            #endif
        #endif
    #endif
    return decaf_succeed_if(mask_to_bool(succ));
}

decaf_error_t
API_NS(invert_elligator_uniform) (
    unsigned char partial_hash[2*SER_BYTES],
    const point_t p,
    uint32_t hint
) {
    point_t pt2;
    API_NS(point_from_hash_nonuniform)(pt2,&partial_hash[SER_BYTES]);
    API_NS(point_sub)(pt2,p,pt2);
    return API_NS(invert_elligator_nonuniform)(partial_hash,pt2,hint);
}
