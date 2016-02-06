/* Copyright (c) 2014-2016 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#define GF_HEADROOM 5
#define LIMB(x) (x##ull)&((1ull<<26)-1), (x##ull)>>26
#define FIELD_LITERAL(a,b,c,d,e) {{LIMB(a),LIMB(b),LIMB(c),LIMB(d),LIMB(e)}}

#define LIMB_PLACE_VALUE(i) (((i)&1)?25:26)

void gf_add_RAW (gf out, const gf a, const gf b) {
    for (unsigned int i=0; i<10; i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
    gf_weak_reduce(out);
}

void gf_sub_RAW (gf out, const gf a, const gf b) {
    uint32_t coe = ((1ull<<26)-1)*2, coo = ((1ull<<25)-1)*2, co0 = coe-36;
    for (unsigned int i=0; i<10; i+=2) {
        out->limb[i] = a->limb[i] - b->limb[i] + ((i==0) ? co0 : coe);
        out->limb[i+1] = a->limb[i+1] - b->limb[i+1] + coo;
    }
    gf_weak_reduce(out);
}

void gf_bias (gf a, int amt) {
    (void) a;
    (void) amt;
}

void gf_weak_reduce (gf a) {
    uint32_t maske = (1ull<<26) - 1, masko = (1ull<<25) - 1;
    uint32_t tmp = a->limb[9] >> 25;
    for (unsigned int i=8; i>0; i-=2) {
        a->limb[i+1] = (a->limb[i+1] & masko) + (a->limb[i]>>26);
        a->limb[i] = (a->limb[i] & maske) + (a->limb[i-1]>>25);
    }
    a->limb[1] = (a->limb[1] & masko) + (a->limb[0]>>26);
    a->limb[0] = (a->limb[0] & maske) + tmp*19;
}

