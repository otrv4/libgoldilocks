from gen_file import gen_file

curve_data_inc_c = gen_file(
    public = False,
    per = "curve",
    name = "curve_%(c_filename)s/curve_data.inc.c",
    doc = """@brief Curve data for %(name)s.""",
    code = """
#define API_NAME "%(c_ns)s"
#define API_NS(_id) %(c_ns)s_##_id
#define API_NS2(_pref,_id) _pref##_%(c_ns)s_##_id

#define SCALAR_BITS %(C_NS)s_SCALAR_BITS

#ifndef DECAF_JUST_API

#define SCALAR_LIMBS %(C_NS)s_SCALAR_LIMBS
#define scalar_t API_NS(scalar_t)
#define point_t API_NS(point_t)
#define precomputed_s API_NS(precomputed_s)
#define IMAGINE_TWIST %(imagine_twist)d
#define COFACTOR %(cofactor)d

static const int EDWARDS_D = %(d)d;

static const scalar_t sc_p = {{{
    %(scalar_p)s
}}};

#ifdef GEN_TABLES
/* Not exported, but used by pregen tool. */
static const unsigned char base_point_ser_for_pregen[SER_BYTES] = {
    %(decaf_base)s
};
#endif

#if COFACTOR==8
    static const gf SQRT_ONE_MINUS_D = {FIELD_LITERAL(
        %(sqrt_one_minus_d)s
    )};
#endif

#endif /* DECAF_JUST_API */
""")