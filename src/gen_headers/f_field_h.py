from gen_file import gen_file

f_field_h = gen_file(
    public = False,
    per = "field",
    name = "p%(gf_shortname)s/f_field.h",
    doc = """@brief Field-specific code for %(gf_desc)s.""",
    code = """
#include "constant_time.h"
#include <string.h>

#include "f_impl.h"
#define GF_LIT_LIMB_BITS  %(gf_lit_limb_bits)d
#define GF_BITS           %(gf_bits)d
#define gf                gf_%(gf_shortname)s_t
#define gf_s              gf_%(gf_shortname)s_s
#define gf_mul            gf_%(gf_shortname)s_mul
#define gf_sqr            gf_%(gf_shortname)s_sqr
#define gf_add_RAW        gf_%(gf_shortname)s_add_RAW
#define gf_sub_RAW        gf_%(gf_shortname)s_sub_RAW
#define gf_mulw           gf_%(gf_shortname)s_mulw
#define gf_bias           gf_%(gf_shortname)s_bias
#define gf_isr            gf_%(gf_shortname)s_isr
#define gf_weak_reduce    gf_%(gf_shortname)s_weak_reduce
#define gf_strong_reduce  gf_%(gf_shortname)s_strong_reduce
#define gf_serialize      gf_%(gf_shortname)s_serialize
#define gf_deserialize    gf_%(gf_shortname)s_deserialize

#define SQRT_MINUS_ONE    P%(gf_shortname)s_SQRT_MINUS_ONE /* might not be defined */
""")