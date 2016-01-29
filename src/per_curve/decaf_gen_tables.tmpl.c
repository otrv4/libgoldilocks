/** @brief Decaf global constant table precomputation. */

#define _XOPEN_SOURCE 600 /* for posix_memalign */
#include <stdio.h>
#include <stdlib.h>

#include "field.h"
#include "f_field.h"
#include "decaf.h"
#include "decaf_config.h"

#define API_NS(_id) $(c_ns)_##_id
#define SCALAR_BITS $(C_NS)_SCALAR_BITS
static const unsigned char base_point_ser_for_pregen[SER_BYTES] = {
    $(decaf_base)
};

 /* To satisfy linker. */
const gf API_NS(precomputed_base_as_fe)[1];
const API_NS(scalar_t) API_NS(precomputed_scalarmul_adjustment);
const API_NS(scalar_t) API_NS(point_scalarmul_adjustment);

const API_NS(point_t) API_NS(point_base);
const uint8_t API_NS(x_base_point)[X_PUBLIC_BYTES] = {0};

struct niels_s;
const gf_s *API_NS(precomputed_wnaf_as_fe);
extern const size_t API_NS(sizeof_precomputed_wnafs);

void API_NS(precompute_wnafs) (
    struct niels_s *out,
    const API_NS(point_t) base
);

static void scalar_print(const char *name, const API_NS(scalar_t) sc) { /* UNIFY */
    printf("const API_NS(scalar_t) %s = {{{\n", name);
    const int SCALAR_BYTES = (SCALAR_BITS + 7) / 8;
    unsigned char ser[SCALAR_BYTES];
    API_NS(scalar_encode)(ser,sc);
    int b=0, i, comma=0;
    unsigned long long limb = 0;
    for (i=0; i<SCALAR_BYTES; i++) {
        limb |= ((uint64_t)ser[i])<<b;
        b += 8;
        if (b == 64 || i==SCALAR_BYTES-1) {
            b = 0;
            if (comma) printf(",");
            comma = 1;
            printf("SC_LIMB(0x%016llx)", limb);
            limb = ((uint64_t)ser[i])>>(8-b);
        }
    }
    printf("}}};\n\n");
}

static void field_print(const gf f) { /* UNIFY */
    unsigned char ser[SER_BYTES];
    gf_serialize(ser,f);
    int b=0, i, comma=0;
    unsigned long long limb = 0;
    printf("{FIELD_LITERAL(");
    for (i=0; i<SER_BYTES; i++) {
        limb |= ((uint64_t)ser[i])<<b;
        b += 8;
        if (b >= GF_LIT_LIMB_BITS || i == SER_BYTES-1) {
            limb &= (1ull<<GF_LIT_LIMB_BITS) -1;
            b -= GF_LIT_LIMB_BITS;
            if (comma) printf(",");
            comma = 1;
            printf("0x%016llx", limb);
            limb = ((uint64_t)ser[i])>>(8-b);
        }
    }
    printf(")}");
    assert(b<8);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    
    API_NS(point_t) real_point_base;
    int ret = API_NS(point_decode)(real_point_base,base_point_ser_for_pregen,0);
    if (ret != DECAF_SUCCESS) return 1;
    
    API_NS(precomputed_s) *pre;
    ret = posix_memalign((void**)&pre, API_NS(alignof_precomputed_s), API_NS(sizeof_precomputed_s));
    if (ret || !pre) return 1;
    API_NS(precompute)(pre, real_point_base);
    
    struct niels_s *preWnaf;
    ret = posix_memalign((void**)&preWnaf, API_NS(alignof_precomputed_s), API_NS(sizeof_precomputed_wnafs));
    if (ret || !preWnaf) return 1;
    API_NS(precompute_wnafs)(preWnaf, real_point_base);

    const gf_s *output;
    unsigned i;
    
    printf("/** @warning: this file was automatically generated. */\n");
    printf("#include \"field.h\"\n\n");
    printf("#include <decaf.h>\n\n");
    printf("#define API_NS(_id) $(c_ns)_##_id\n");
    
    output = (const gf_s *)real_point_base;
    printf("const API_NS(point_t) API_NS(point_base) = {{\n");
    for (i=0; i < sizeof(API_NS(point_t)); i+=sizeof(gf)) {
        if (i) printf(",\n  ");
        field_print(output++);
    }
    printf("\n}};\n");
    
    output = (const gf_s *)pre;
    printf("const gf API_NS(precomputed_base_as_fe)[%d]\n", 
        (int)(API_NS(sizeof_precomputed_s) / sizeof(gf)));
    printf("__attribute__((aligned(%d),visibility(\"hidden\"))) = {\n  ", (int)API_NS(alignof_precomputed_s));
    
    for (i=0; i < API_NS(sizeof_precomputed_s); i+=sizeof(gf)) {
        if (i) printf(",\n  ");
        field_print(output++);
    }
    printf("\n};\n");
    
    output = (const gf_s *)preWnaf;
    printf("const gf API_NS(precomputed_wnaf_as_fe)[%d]\n", 
        (int)(API_NS(sizeof_precomputed_wnafs) / sizeof(gf)));
    printf("__attribute__((aligned(%d),visibility(\"hidden\"))) = {\n  ", (int)API_NS(alignof_precomputed_s));
    for (i=0; i < API_NS(sizeof_precomputed_wnafs); i+=sizeof(gf)) {
        if (i) printf(",\n  ");
        field_print(output++);
    }
    printf("\n};\n");
    
    API_NS(scalar_t) smadj;
    API_NS(scalar_copy)(smadj,API_NS(scalar_one));

    for (i=0; i<DECAF_COMBS_N*DECAF_COMBS_T*DECAF_COMBS_S; i++) {
        API_NS(scalar_add)(smadj,smadj,smadj);
    }
    API_NS(scalar_sub)(smadj, smadj, API_NS(scalar_one));
    scalar_print("API_NS(precomputed_scalarmul_adjustment)", smadj);
    
    API_NS(scalar_copy)(smadj,API_NS(scalar_one));
    for (i=0; i<SCALAR_BITS-1 + DECAF_WINDOW_BITS
            - ((SCALAR_BITS-1) % DECAF_WINDOW_BITS); i++) {
        API_NS(scalar_add)(smadj,smadj,smadj);
    }
    API_NS(scalar_sub)(smadj, smadj, API_NS(scalar_one));
    scalar_print("API_NS(point_scalarmul_adjustment)", smadj);
    
    
    API_NS(scalar_sub)(smadj,API_NS(scalar_zero),API_NS(scalar_one)); /* get p-1 */

    /* Generate the Montgomery ladder version of the base point */
    gf base1,base2;
    ret = gf_deserialize(base1,base_point_ser_for_pregen);
    if (ret != DECAF_SUCCESS) return 1;
    gf_sqr(base2,base1);
    uint8_t x_ser[X_PUBLIC_BYTES] = {0};
    gf_serialize(x_ser, base2);
    printf("const uint8_t API_NS(x_base_point)[%d] = {", X_PUBLIC_BYTES);
    for (i=0; i<X_PUBLIC_BYTES; i++) {
        printf("%s%s%d",i?",":"",(i%32==0)?"\n  ":"",x_ser[i]);
    }
    printf("\n};\n");
    
    return 0;
}
