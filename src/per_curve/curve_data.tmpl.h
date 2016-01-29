#define API_NAME "$(c_ns)"
#define API_NS(_id) $(c_ns)_##_id
#define API_NS2(_pref,_id) _pref##_$(c_ns)_##_id

#define SCALAR_BITS $(C_NS)_SCALAR_BITS

#ifndef DECAF_JUST_API

#define SCALAR_LIMBS $(C_NS)_SCALAR_LIMBS
#define scalar_t API_NS(scalar_t)
#define point_t API_NS(point_t)
#define precomputed_s API_NS(precomputed_s)
#define IMAGINE_TWIST $(imagine_twist)
#define COFACTOR $(cofactor)

static const int EDWARDS_D = $(d);

static const scalar_t sc_p = {{{
    $(scalar_p)
}}};

#ifdef GEN_TABLES
/* Not exported, but used by pregen tool. */
static const unsigned char base_point_ser_for_pregen[SER_BYTES] = {
    $(decaf_base)
};
#endif

#if COFACTOR==8
    static const gf SQRT_ONE_MINUS_D = {FIELD_LITERAL(
        $(sqrt_one_minus_d)
    )};
#endif

#endif /* DECAF_JUST_API */
