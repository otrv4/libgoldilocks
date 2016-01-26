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
#include <decaf/spongerng.hxx>
#include <decaf/crypto.h>
#include <decaf/crypto.hxx>
#include <stdio.h>

using namespace decaf;

static bool passing = true;
static const long NTESTS = 10000;

class Test {
public:
    bool passing_now;
    Test(const char *test) {
        passing_now = true;
        printf("%s...", test);
        if (strlen(test) < 27) printf("%*s",int(27-strlen(test)),"");
        fflush(stdout);
    }
    ~Test() {
        if (std::uncaught_exception()) {
            fail();
            printf("  due to uncaught exception.\n");
        }
        if (passing_now) printf("[PASS]\n");
    }
    void fail() {
        if (!passing_now) return;
        passing_now = passing = false;
        printf("[FAIL]\n");
    }
};

template<typename Group> struct Tests {

typedef typename Group::Scalar Scalar;
typedef typename Group::Point Point;
typedef typename Group::DhLadder DhLadder;
typedef typename Group::Precomputed Precomputed;

static void print(const char *name, const Scalar &x) {
    unsigned char buffer[Scalar::SER_BYTES];
    x.serialize_into(buffer);
    printf("  %s = 0x", name);
    for (int i=sizeof(buffer)-1; i>=0; i--) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

static void hexprint(const char *name, const SecureBuffer &buffer) {
    printf("  %s = 0x", name);
    for (int i=buffer.size()-1; i>=0; i--) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

static void print(const char *name, const Point &x) {
    unsigned char buffer[Point::SER_BYTES];
    x.serialize_into(buffer);
    printf("  %s = 0x", name);
    for (int i=Point::SER_BYTES-1; i>=0; i--) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

static bool arith_check(
    Test &test,
    const Scalar &x,
    const Scalar &y,
    const Scalar &z,
    const Scalar &l,
    const Scalar &r,
    const char *name
) {
    if (l == r) return true;
    test.fail();
    printf("  %s", name);
    print("x", x);
    print("y", y);
    print("z", z);
    print("lhs", l);
    print("rhs", r);
    return false;
}

static bool point_check(
    Test &test,
    const Point &p,
    const Point &q,
    const Point &R,
    const Scalar &x,
    const Scalar &y,
    const Point &l,
    const Point &r,
    const char *name
) {
    bool good = l==r;
    if (!p.validate()) { good = false; printf("  p invalid\n"); }
    if (!q.validate()) { good = false; printf("  q invalid\n"); }
    if (!r.validate()) { good = false; printf("  r invalid\n"); }
    if (!l.validate()) { good = false; printf("  l invalid\n"); }
    if (good) return true;
    
    test.fail();
    printf("  %s", name);
    print("x", x);
    print("y", y);
    print("p", p);
    print("q", q);
    print("r", R);
    print("lhs", r);
    print("rhs", l);
    return false;
}

static void test_arithmetic() {
    SpongeRng rng(Block("test_arithmetic"),SpongeRng::DETERMINISTIC);
    
    Test test("Arithmetic");
    Scalar x(0),y(0),z(0);
    arith_check(test,x,y,z,INT_MAX,(decaf_word_t)INT_MAX,"cast from max");
    arith_check(test,x,y,z,INT_MIN,-Scalar(1+(decaf_word_t)INT_MAX),"cast from min");
        
    for (int i=0; i<NTESTS*10 && test.passing_now; i++) {
        /* TODO: pathological cases */
        size_t sob = DECAF_255_SCALAR_BYTES + 8 - (i%16);
        Scalar x(rng.read(sob));
        Scalar y(rng.read(sob));
        Scalar z(rng.read(sob));
        

        arith_check(test,x,y,z,x+y,y+x,"commute add");
        arith_check(test,x,y,z,x,x+0,"ident add");
        arith_check(test,x,y,z,x,x-0,"ident sub");
        arith_check(test,x,y,z,x+(y+z),(x+y)+z,"assoc add");
        arith_check(test,x,y,z,x*(y+z),x*y + x*z,"distributive mul/add");
        arith_check(test,x,y,z,x*(y-z),x*y - x*z,"distributive mul/add");
        arith_check(test,x,y,z,x*(y*z),(x*y)*z,"assoc mul");
        arith_check(test,x,y,z,x*y,y*x,"commute mul");
        arith_check(test,x,y,z,x,x*1,"ident mul");
        arith_check(test,x,y,z,0,x*0,"mul by 0");
        arith_check(test,x,y,z,-x,x*-1,"mul by -1");
        arith_check(test,x,y,z,x+x,x*2,"mul by 2");
        
        if (i%20) continue;
        if (y!=0) arith_check(test,x,y,z,x*y/y,x,"invert");
        try {
            y = x/0;
            test.fail();
            printf("  Inverted zero!");
            print("x", x);
            print("y", y);
        } catch(CryptoException) {}
    }
}

static void test_elligator() {
    SpongeRng rng(Block("test_elligator"),SpongeRng::DETERMINISTIC);
    Test test("Elligator");
    
    const int NHINTS = Group::REMOVED_COFACTOR * 2;
    SecureBuffer *alts[NHINTS];
    bool successes[NHINTS];
    SecureBuffer *alts2[NHINTS];
    bool successes2[NHINTS];

    for (int i=0; i<NTESTS/10 && (test.passing_now || i < 100); i++) {
        size_t len =  (i % (2*Point::HASH_BYTES + 3));
        SecureBuffer b1(len);
        if (i!=Point::HASH_BYTES) rng.read(b1); /* special test case */
        if (i==1) b1[0] = 1; /* special case test */
        if (len >= Point::HASH_BYTES) b1[Point::HASH_BYTES-1] &= 0x7F; // FIXME MAGIC
        
        Point s = Point::from_hash(b1), ss=s;
        for (int j=0; j<(i&3); j++) ss = ss.debugging_torque();
        
        ss = ss.debugging_pscale(rng);
        
        bool good = false;
        for (int j=0; j<NHINTS; j++) {
            alts[j] = new SecureBuffer(len);
            alts2[j] = new SecureBuffer(len);

            if (len > Point::HASH_BYTES)
                memcpy(&(*alts[j])[Point::HASH_BYTES], &b1[Point::HASH_BYTES], len-Point::HASH_BYTES);
            
            if (len > Point::HASH_BYTES)
                memcpy(&(*alts2[j])[Point::HASH_BYTES], &b1[Point::HASH_BYTES], len-Point::HASH_BYTES);
            
            successes[j]  = decaf_successful( s.invert_elligator(*alts[j], j));
            successes2[j] = decaf_successful(ss.invert_elligator(*alts2[j],j));
            
            if (successes[j] != successes2[j]
                || (successes[j] && successes2[j] && *alts[j] != *alts2[j])
            ) {
                test.fail();
                printf("   Unscalable Elligator inversion: i=%d, hint=%d, s=%d,%d\n",i,j,
                    -int(successes[j]),-int(successes2[j]));
                hexprint("x",b1);
                hexprint("X",*alts[j]);
                hexprint("X",*alts2[j]);
            }
           
            if (successes[j]) {
                good = good || (b1 == *alts[j]);
                for (int k=0; k<j; k++) {
                    if (successes[k] && *alts[j] == *alts[k]) {
                        test.fail();
                        printf("   Duplicate Elligator inversion: i=%d, hints=%d, %d\n",i,j,k);
                        hexprint("x",b1);
                        hexprint("X",*alts[j]);
                    }
                }
                if (s != Point::from_hash(*alts[j])) {
                    test.fail();
                    printf("   Fail Elligator inversion round-trip: i=%d, hint=%d %s\n",i,j,
                        (s==-Point::from_hash(*alts[j])) ? "[output was -input]": "");
                    hexprint("x",b1);
                    hexprint("X",*alts[j]);
                }
            }
        }
        
        if (!good) {
            test.fail();
            printf("   %s Elligator inversion: i=%d\n",good ? "Passed" : "Failed", i);
            hexprint("B", b1);
            for (int j=0; j<NHINTS; j++) {
                printf("  %d: %s%s", j, successes[j] ? "succ" : "fail\n", (successes[j] && *alts[j] == b1) ? " [x]" : "");
                if (successes[j]) {
                    hexprint("b", *alts[j]);
                }
            }
            printf("\n");
        }
        
        for (int j=0; j<NHINTS; j++) {
            delete alts[j];
            alts[j] = NULL;
            delete alts2[j];
            alts2[j] = NULL;
        }
        
        Point t(rng);
        point_check(test,t,t,t,0,0,t,Point::from_hash(t.steg_encode(rng)),"steg round-trip");
        
        
        
        
    }
}

static void test_ec() {
    SpongeRng rng(Block("test_ec"),SpongeRng::DETERMINISTIC);
    
    Test test("EC");

    Point id = Point::identity(), base = Point::base();
    point_check(test,id,id,id,0,0,Point::from_hash(""),id,"fh0");
    
    if (Group::FIELD_MODULUS_TYPE == 3) {
        /* When p == 3 mod 4, the QNR is -1, so u*1^2 = -1 also produces the
         * identity.
         */
        point_check(test,id,id,id,0,0,Point::from_hash("\x01"),id,"fh1");
    }
    
    for (int i=0; i<NTESTS && test.passing_now; i++) {
        /* TODO: pathological cases */
        Scalar x(rng);
        Scalar y(rng);
        Point p(rng);
        Point q(rng);
        
        Point d1, d2;
        
        SecureBuffer buffer(2*Point::HASH_BYTES);
        rng.read(buffer);
        Point r = Point::from_hash(buffer);
        
        point_check(test,p,q,r,0,0,p,Point(p.serialize()),"round-trip");
        Point pp = p.debugging_torque().debugging_pscale(rng);
        if (!memeq(pp.serialize(),p.serialize())) {
            test.fail();
            printf("Fail torque seq test\n");
        }
        point_check(test,p,q,r,0,0,p,pp,"torque eq");
        point_check(test,p,q,r,0,0,p+q,q+p,"commute add");
        point_check(test,p,q,r,0,0,(p-q)+q,p,"correct sub");
        point_check(test,p,q,r,0,0,p+(q+r),(p+q)+r,"assoc add");
        point_check(test,p,q,r,0,0,p.times_two(),p+p,"dbl add");
        
        if (i%10) continue;
        point_check(test,p,q,r,x,0,x*(p+q),x*p+x*q,"distr mul");
        point_check(test,p,q,r,x,y,(x*y)*p,x*(y*p),"assoc mul");
        point_check(test,p,q,r,x,y,x*p+y*q,Point::double_scalarmul(x,p,y,q),"double mul");
        
        p.dual_scalarmul(d1,d2,x,y);
        point_check(test,p,q,r,x,y,x*p,d1,"dual mul 1");
        point_check(test,p,q,r,x,y,y*p,d2,"dual mul 2");
        
        point_check(test,base,q,r,x,y,x*base+y*q,q.non_secret_combo_with_base(y,x),"ds vt mul");
        point_check(test,p,q,r,x,0,Precomputed(p)*x,p*x,"precomp mul");
        point_check(test,p,q,r,0,0,r,
            Point::from_hash(Buffer(buffer).slice(0,Point::HASH_BYTES))
            + Point::from_hash(Buffer(buffer).slice(Point::HASH_BYTES,Point::HASH_BYTES)),
            "unih = hash+add"
        );
            
        point_check(test,p,q,r,x,0,Point(x.direct_scalarmul(p.serialize())),x*p,"direct mul");
    }
}

static void test_crypto() {
    Test test("Sample crypto");
    SpongeRng rng(Block("test_decaf_crypto"),SpongeRng::DETERMINISTIC);

    for (int i=0; i<NTESTS && test.passing_now; i++) {
        PrivateKey<Group> priv1(rng), priv2(rng);
        PublicKey<Group> pub1(priv1), pub2(priv2);
        
        SecureBuffer message = rng.read(i);
        SecureBuffer sig(priv1.sign(message));

        pub1.verify(message, sig);
        
        SecureBuffer s1(priv1.sharedSecret(pub2,32,true));
        SecureBuffer s2(priv2.sharedSecret(pub1,32,false));
        if (!memeq(s1,s2)) {
            test.fail();
            printf("    Shared secrets disagree on iteration %d.\n",i);
        }
    }
}

static const uint8_t rfc7748_1[DhLadder::PUBLIC_BYTES];
static const uint8_t rfc7748_1000[DhLadder::PUBLIC_BYTES];
static const uint8_t rfc7748_1000000[DhLadder::PUBLIC_BYTES];

static void test_cfrg_crypto() {
    Test test("CFRG crypto");
    SpongeRng rng(Block("test_cfrg_crypto"),SpongeRng::DETERMINISTIC);
    for (int i=0; i<NTESTS && test.passing_now; i++) {
        
        FixedArrayBuffer<DhLadder::PUBLIC_BYTES> base(rng);
        FixedArrayBuffer<DhLadder::PRIVATE_BYTES> s1(rng), s2(rng);
        
        SecureBuffer p1  = DhLadder::shared_secret(base,s1);
        SecureBuffer p2  = DhLadder::shared_secret(base,s2);
        SecureBuffer ss1 = DhLadder::shared_secret(p2,s1);
        SecureBuffer ss2 = DhLadder::shared_secret(p1,s2);

        if (!memeq(ss1,ss2)) {
            test.fail();
            printf("    Shared secrets disagree on iteration %d.\n",i);
        }
        
        if (!memeq(
            DhLadder::shared_secret(DhLadder::base_point(),s1),
            DhLadder::generate_key(s1)
        )) {
            test.fail();
            printf("    Generated keys disagree on iteration %d.\n",i);
        }
    }
}

static void test_cfrg_vectors() {
    Test test("CFRG test vectors");
    SecureBuffer k = DhLadder::base_point();
    SecureBuffer u = DhLadder::base_point();
    
    int the_ntests = (NTESTS < 1000000) ? 1000 : 1000000;
    
    for (int i=0; i<the_ntests && test.passing_now; i++) {
        SecureBuffer n = DhLadder::shared_secret(u,k);
        u = k; k = n;
        if (i==1-1) {
            if (!memeq(k,SecureBuffer(FixedBlock<DhLadder::PUBLIC_BYTES>(rfc7748_1)))) {
                test.fail();
                printf("    Test vectors disagree at 1.");
            }
        } else if (i==1000-1) {
            if (!memeq(k,SecureBuffer(FixedBlock<DhLadder::PUBLIC_BYTES>(rfc7748_1000)))) {
                test.fail();
                printf("    Test vectors disagree at 1000.");
            }
        } else if (i==1000000-1) {
            if (!memeq(k,SecureBuffer(FixedBlock<DhLadder::PUBLIC_BYTES>(rfc7748_1000000)))) {
                test.fail();
                printf("    Test vectors disagree at 1000000.");
            }
        }
    }
}

}; /* template<GroupId GROUP> struct Tests */

template<> const uint8_t Tests<IsoEd25519>::rfc7748_1[32] = {
    0x42,0x2c,0x8e,0x7a,0x62,0x27,0xd7,0xbc,
    0xa1,0x35,0x0b,0x3e,0x2b,0xb7,0x27,0x9f,
    0x78,0x97,0xb8,0x7b,0xb6,0x85,0x4b,0x78,
    0x3c,0x60,0xe8,0x03,0x11,0xae,0x30,0x79
};
template<> const uint8_t Tests<IsoEd25519>::rfc7748_1000[32] = {
    0x68,0x4c,0xf5,0x9b,0xa8,0x33,0x09,0x55,
    0x28,0x00,0xef,0x56,0x6f,0x2f,0x4d,0x3c,
    0x1c,0x38,0x87,0xc4,0x93,0x60,0xe3,0x87,
    0x5f,0x2e,0xb9,0x4d,0x99,0x53,0x2c,0x51
};
template<> const uint8_t Tests<IsoEd25519>::rfc7748_1000000[32] = {
    0x7c,0x39,0x11,0xe0,0xab,0x25,0x86,0xfd,
    0x86,0x44,0x97,0x29,0x7e,0x57,0x5e,0x6f,
    0x3b,0xc6,0x01,0xc0,0x88,0x3c,0x30,0xdf,
    0x5f,0x4d,0xd2,0xd2,0x4f,0x66,0x54,0x24
};
template<> const uint8_t Tests<Ed448Goldilocks>::rfc7748_1[56] = {
    0x3f,0x48,0x2c,0x8a,0x9f,0x19,0xb0,0x1e,
    0x6c,0x46,0xee,0x97,0x11,0xd9,0xdc,0x14,
    0xfd,0x4b,0xf6,0x7a,0xf3,0x07,0x65,0xc2,
    0xae,0x2b,0x84,0x6a,0x4d,0x23,0xa8,0xcd,
    0x0d,0xb8,0x97,0x08,0x62,0x39,0x49,0x2c,
    0xaf,0x35,0x0b,0x51,0xf8,0x33,0x86,0x8b,
    0x9b,0xc2,0xb3,0xbc,0xa9,0xcf,0x41,0x13
};
template<> const uint8_t Tests<Ed448Goldilocks>::rfc7748_1000[56] = {
    0xaa,0x3b,0x47,0x49,0xd5,0x5b,0x9d,0xaf,
    0x1e,0x5b,0x00,0x28,0x88,0x26,0xc4,0x67,
    0x27,0x4c,0xe3,0xeb,0xbd,0xd5,0xc1,0x7b,
    0x97,0x5e,0x09,0xd4,0xaf,0x6c,0x67,0xcf,
    0x10,0xd0,0x87,0x20,0x2d,0xb8,0x82,0x86,
    0xe2,0xb7,0x9f,0xce,0xea,0x3e,0xc3,0x53,
    0xef,0x54,0xfa,0xa2,0x6e,0x21,0x9f,0x38
};
template<> const uint8_t Tests<Ed448Goldilocks>::rfc7748_1000000[56] = {
    0x07,0x7f,0x45,0x36,0x81,0xca,0xca,0x36,
    0x93,0x19,0x84,0x20,0xbb,0xe5,0x15,0xca,
    0xe0,0x00,0x24,0x72,0x51,0x9b,0x3e,0x67,
    0x66,0x1a,0x7e,0x89,0xca,0xb9,0x46,0x95,
    0xc8,0xf4,0xbc,0xd6,0x6e,0x61,0xb9,0xb9,
    0xc9,0x46,0xda,0x8d,0x52,0x4d,0xe3,0xd6,
    0x9b,0xd9,0xd9,0xd6,0x6b,0x99,0x7e,0x37
};
        
    

int main(int argc, char **argv) {
    (void) argc; (void) argv;
    
    printf("Testing %s:\n",IsoEd25519::name());
    Tests<IsoEd25519>::test_arithmetic();
    Tests<IsoEd25519>::test_elligator();
    Tests<IsoEd25519>::test_ec();
    Tests<IsoEd25519>::test_cfrg_crypto();
    Tests<IsoEd25519>::test_cfrg_vectors();
    Tests<IsoEd25519>::test_crypto();
    
    printf("\n");
    printf("Testing %s:\n", Ed448Goldilocks::name());
    Tests<Ed448Goldilocks>::test_arithmetic();
    Tests<Ed448Goldilocks>::test_elligator();
    Tests<Ed448Goldilocks>::test_ec();
    Tests<Ed448Goldilocks>::test_cfrg_crypto();
    Tests<Ed448Goldilocks>::test_cfrg_vectors();
    Tests<Ed448Goldilocks>::test_crypto();
    
    if (passing) printf("Passed all tests.\n");
    
    return passing ? 0 : 1;
}
