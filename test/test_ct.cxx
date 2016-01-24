/**
 * @file test_decaf.cxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief C++ tests, because that's easier.
 */

#include <decaf.hxx>
#include <decaf/shake.hxx>
#include <decaf/crypto.h>
#include <decaf/crypto.hxx>
#include <stdio.h>
#include <memcheck.h>

using namespace decaf;

static const long NTESTS = 100;

const char *undef_str = "Valgrind thinks this string is undefined."
const Block undef_block(undef_str);

template<typename Group> struct Tests {

typedef typename Group::Scalar Scalar;
typedef typename Group::Point Point;
typedef typename Group::Precomputed Precomputed;

static void test_arithmetic() {
    SpongeRng rng(Block("test_arithmetic"));
    rng.stir(undef_str);
    
    Test test("Arithmetic");
    Scalar x(rng),y(rng),z;
    FixedBlock<Group::Scalar::SER_BYTES> Ser;
        
    for (int i=0; i<NTESTS; i++) {
        (void)(x+y);
        (void)(x-y);
        (void)(x*y);
        (void)(x/y); // Probably fails?
        (void)(x==y);
        (void)(z=y);
        x.serialize(ser);
        x = y;
    }
}

static void test_elligator() {
    SpongeRng rng(Block("test_elligator"));
    rng.stir(undef_str);
        
    for (int i=0; i<NTESTS; i++) {
        Point x(rng);
        (void)x;
        /* TODO: uniform, nonuniform... */
    }
}

static void test_ec() {
    SpongeRng rng(Block("test_ec"));
    rng.stir(undef_str);

    for (int i=0; i<NTESTS; i++) {
        Scalar y(rng),z(rng);
        Point p(rng),q(rng),r;
        
        (void)(p*y);
        (void)(p+q);
        (void)(p-q);
        (void)(-p);
        (void)(p.times_two());
        (void)(p==q);
        (void)(p.debugging_torque());
        (void)(p.non_secret_combo_with_base(y,z)); // Should fail
        (void)(Precomputed(p)*y);
        p.dual_scalarmul(q,r,y,z);
        p.double_scalarmul(q,r,y,z);
        
    }
}

static void test_crypto() {
    /* TODO */
}

}; // template<GroupId GROUP>

int main(int argc, char **argv) {
    (void) argc; (void) argv;
    
    VALGRIND_MAKE_MEM_UNDEFINED(undef_str, strlen(undef_str));
    
    printf("Testing %s:\n",IsoEd25519::name());
    Tests<IsoEd25519>::test_arithmetic();
    Tests<IsoEd25519>::test_elligator();
    Tests<IsoEd25519>::test_ec();
    Tests<IsoEd25519>::test_crypto();
    
    printf("\n");
    printf("Testing %s:\n", Ed448Goldilocks::name());
    Tests<Ed448Goldilocks>::test_arithmetic();
    Tests<Ed448Goldilocks>::test_elligator();
    Tests<Ed448Goldilocks>::test_ec();
    Tests<Ed448Goldilocks>::test_crypto();
    
    if (passing) printf("Passed all tests.\n");
    
    return passing ? 0 : 1;
}
