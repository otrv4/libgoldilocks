from gen_file import gen_file

f_field_h = gen_file(
    public = False,
    per = "field",
    name = "p%(gf_shortname)s/f_field.h",
    doc = """@brief Field-specific code for %(gf_desc)s.""",
    code = """
#include "constant_time.h"
#include <string.h>
#include <assert.h>

#include "word.h"

#define __DECAF_%(gf_shortname)s_GF_DEFINED__ 1
#define NLIMBS (%(gf_impl_bits)d/sizeof(word_t)/8)
typedef struct gf_%(gf_shortname)s_s {
    word_t limb[NLIMBS];
} __attribute__((aligned(32))) gf_%(gf_shortname)s_s, gf_%(gf_shortname)s_t[1];

#define GF_LIT_LIMB_BITS  %(gf_lit_limb_bits)d
#define GF_BITS           %(gf_bits)d
#define gf                gf_%(gf_shortname)s_t
#define gf_s              gf_%(gf_shortname)s_s
#define gf_copy           gf_%(gf_shortname)s_copy
#define gf_add_RAW        gf_%(gf_shortname)s_add_RAW
#define gf_sub_RAW        gf_%(gf_shortname)s_sub_RAW
#define gf_bias           gf_%(gf_shortname)s_bias
#define gf_weak_reduce    gf_%(gf_shortname)s_weak_reduce
#define gf_strong_reduce  gf_%(gf_shortname)s_strong_reduce
#define gf_mul            gf_%(gf_shortname)s_mul
#define gf_sqr            gf_%(gf_shortname)s_sqr
#define gf_mulw           gf_%(gf_shortname)s_mulw
#define gf_isr            gf_%(gf_shortname)s_isr
#define gf_serialize      gf_%(gf_shortname)s_serialize
#define gf_deserialize    gf_%(gf_shortname)s_deserialize
#define MODULUS           gf_%(gf_shortname)s_MODULUS

#define SQRT_MINUS_ONE    P%(gf_shortname)s_SQRT_MINUS_ONE /* might not be defined */

#define INLINE_UNUSED __inline__ __attribute__((unused,always_inline))

#ifdef __cplusplus
extern "C" {
#endif

const gf MODULUS;

/* Defined below in f_impl.h */
static INLINE_UNUSED void gf_copy (gf out, const gf a) { *out = *a; }
static INLINE_UNUSED void gf_add_RAW (gf out, const gf a, const gf b);
static INLINE_UNUSED void gf_sub_RAW (gf out, const gf a, const gf b);
static INLINE_UNUSED void gf_bias (gf inout, int amount);
static INLINE_UNUSED void gf_weak_reduce (gf inout);

void gf_strong_reduce (gf inout);   
void gf_mul (gf_s *__restrict__ out, const gf a, const gf b);
void gf_mulw (gf_s *__restrict__ out, const gf a, uint64_t b);
void gf_sqr (gf_s *__restrict__ out, const gf a);
void gf_serialize (uint8_t *serial, const gf x);
mask_t gf_deserialize (gf x, const uint8_t serial[(GF_BITS-1)/8+1]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#include "f_impl.h" /* Bring in the inline implementations */

#ifndef LIMBPERM
  #define LIMBPERM(i) (i)
#endif
#define LIMB_MASK(i) (((1ull)<<LIMB_PLACE_VALUE(i))-1)
""")
