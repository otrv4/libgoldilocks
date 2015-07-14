#define SCALAR_LIMBS DECAF_448_SCALAR_LIMBS
#define SCALAR_BITS DECAF_448_SCALAR_BITS
#define NLIMBS DECAF_448_LIMBS
#define API_NS(_id) decaf_448_##_id
#define API_NS2(_pref,_id) _pref##_decaf_448_##_id
#define scalar_t decaf_448_scalar_t
#define point_t decaf_448_point_t
#define precomputed_s decaf_448_precomputed_s
#define SER_BYTES DECAF_448_SER_BYTES
#define IMAGINE_TWIST 0
#define P_MOD_8 7
#define COFACTOR 4

static const int EDWARDS_D = -39081;

static const scalar_t sc_p = {{{
    SC_LIMB(0x2378c292ab5844f3),
    SC_LIMB(0x216cc2728dc58f55),
    SC_LIMB(0xc44edb49aed63690),
    SC_LIMB(0xffffffff7cca23e9),
    SC_LIMB(0xffffffffffffffff),
    SC_LIMB(0xffffffffffffffff),
    SC_LIMB(0x3fffffffffffffff)
}}};
 
/* sqrt(5) = 2phi-1 from the curve spec.  Not exported, but used by pregen tool. */
const unsigned char base_point_ser_for_pregen[SER_BYTES] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,1
};