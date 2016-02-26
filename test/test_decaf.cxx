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

static uint64_t leint(const SecureBuffer &xx) {
    uint64_t out = 0;
    for (unsigned int i=0; i<xx.size() && i<sizeof(out); i++) {
        out |= uint64_t(xx[i]) << (8*i);
    }
    return out;
}

template<typename Group> struct Tests {

typedef typename Group::Scalar Scalar;
typedef typename Group::Point Point;
typedef typename Group::DhLadder DhLadder;
typedef typename Group::EdDSA EdDSA;
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
        size_t sob = i % (2*Group::Scalar::SER_BYTES);
        
        SecureBuffer xx = rng.read(sob), yy = rng.read(sob), zz = rng.read(sob);
        
        Scalar x(xx);
        Scalar y(yy);
        Scalar z(zz);

        arith_check(test,x,y,z,x+y,y+x,"commute add");
        arith_check(test,x,y,z,x,x+0,"ident add");
        arith_check(test,x,y,z,x,x-0,"ident sub");
        arith_check(test,x,y,z,x+-x,0,"inverse add");
        arith_check(test,x,y,z,x-x,0,"inverse sub");
        arith_check(test,x,y,z,x-(x+1),-1,"inverse add2");
        arith_check(test,x,y,z,x+(y+z),(x+y)+z,"assoc add");
        arith_check(test,x,y,z,x*(y+z),x*y + x*z,"distributive mul/add");
        arith_check(test,x,y,z,x*(y-z),x*y - x*z,"distributive mul/add");
        arith_check(test,x,y,z,x*(y*z),(x*y)*z,"assoc mul");
        arith_check(test,x,y,z,x*y,y*x,"commute mul");
        arith_check(test,x,y,z,x,x*1,"ident mul");
        arith_check(test,x,y,z,0,x*0,"mul by 0");
        arith_check(test,x,y,z,-x,x*-1,"mul by -1");
        arith_check(test,x,y,z,x+x,x*2,"mul by 2");
        arith_check(test,x,y,z,-(x*y),(-x)*y,"neg prop mul");
        arith_check(test,x,y,z,x*y,(-x)*(-y),"double neg prop mul");
        arith_check(test,x,y,z,-(x+y),(-x)+(-y),"neg prop add");
        arith_check(test,x,y,z,x-y,(x)+(-y),"add neg sub");
        arith_check(test,x,y,z,(-x)-y,-(x+y),"neg add");
        
        if (sob <= 4) {
            uint64_t xi = leint(xx), yi = leint(yy);
            arith_check(test,x,y,z,x,xi,"parse consistency");
            arith_check(test,x,y,z,x+y,xi+yi,"add consistency");
            arith_check(test,x,y,z,x*y,xi*yi,"mul consistency");
        }
        
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

static const Block sqrt_minus_one;
static const Block minus_sqrt_minus_one;
static const Block elli_patho; /* sqrt(1/(u(1-d))) */

static void test_elligator() {
    SpongeRng rng(Block("test_elligator"),SpongeRng::DETERMINISTIC);
    Test test("Elligator");
    
    const int NHINTS = 1<<Point::INVERT_ELLIGATOR_WHICH_BITS;
    SecureBuffer *alts[NHINTS];
    bool successes[NHINTS];
    SecureBuffer *alts2[NHINTS];
    bool successes2[NHINTS];

    for (int i=0; i<NTESTS/10 && (i<10 || test.passing_now); i++) {
        size_t len =  (i % (2*Point::HASH_BYTES + 3));
        SecureBuffer b1(len);
        if (i!=Point::HASH_BYTES) rng.read(b1); /* special test case */
        
        /* Pathological cases */
        if (i==1) b1[0] = 1;
        if (i==2 && sqrt_minus_one.size()) b1 = sqrt_minus_one;
        if (i==3 && minus_sqrt_minus_one.size()) b1 = minus_sqrt_minus_one;
        if (i==4 && elli_patho.size()) b1 = elli_patho;
        len = b1.size();
        
        
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
    
    unsigned char enc[Point::SER_BYTES] = {0};
    
    if (Group::FIELD_MODULUS_TYPE == 3) {
        /* When p == 3 mod 4, the QNR is -1, so u*1^2 = -1 also produces the
         * identity.
         */
        point_check(test,id,id,id,0,0,Point::from_hash("\x01"),id,"fh1");
    }
    
    point_check(test,id,id,id,0,0,Point(FixedBlock<sizeof(enc)>(enc)),id,"decode [0]");
    try {
        enc[0] = 1;
        Point f((FixedBlock<sizeof(enc)>(enc)));
        test.fail();
        printf("    Allowed deserialize of [1]: %d", f==id);
    } catch (CryptoException) {
        /* ok */
    }
    
    if (sqrt_minus_one.size()) {
        try {
            Point f(sqrt_minus_one);
            test.fail();
            printf("    Allowed deserialize of [i]: %d", f==id);
        } catch (CryptoException) {
            /* ok */
        }
    }
    
    if (minus_sqrt_minus_one.size()) {
        try {
            Point f(minus_sqrt_minus_one);
            test.fail();
            printf("    Allowed deserialize of [-i]: %d", f==id);
        } catch (CryptoException) {
            /* ok */
        }
    }
    
    for (int i=0; i<NTESTS && test.passing_now; i++) {
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
            printf("    Fail torque seq test\n");
        }
        if (!memeq((p-pp).serialize(),id.serialize())) {
            test.fail();
            printf("    Fail torque id test\n");
        }
        if (!memeq((p-p).serialize(),id.serialize())) {
            test.fail();
            printf("    Fail id test\n");
        }
        point_check(test,p,q,r,0,0,p,pp,"torque eq");
        point_check(test,p,q,r,0,0,p+q,q+p,"commute add");
        point_check(test,p,q,r,0,0,(p-q)+q,p,"correct sub");
        point_check(test,p,q,r,0,0,p+(q+r),(p+q)+r,"assoc add");
        point_check(test,p,q,r,0,0,p.times_two(),p+p,"dbl add");
        
        if (i%10) continue;
        point_check(test,p,q,r,0,0,p.times_two(),p*Scalar(2),"add times two");
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
        
        q=p;
        for (int j=1; j<Group::REMOVED_COFACTOR; j<<=1) q = q.times_two();
        decaf_error_t error = r.decode_like_eddsa(p.encode_like_eddsa());
        if (error != DECAF_SUCCESS) {
            test.fail();
            printf("    Decode like EdDSA failed.");
        }
        point_check(test,-q,q,r,0,0,q,r,"Encode like EdDSA round-trip");
        
    }
}

static void test_crypto() {
    Test test("Sample crypto");
    SpongeRng rng(Block("test_decaf_crypto"),SpongeRng::DETERMINISTIC);

    for (int i=0; i<NTESTS && test.passing_now; i++) {
        try {
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
        } catch (CryptoException) {
            test.fail();
            printf("    Threw CryptoException.\n");
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

static const Block eddsa_sk, eddsa_pk, eddsa_sig0;

static void test_cfrg_vectors() {
    Test test("CFRG test vectors");
    SecureBuffer k = DhLadder::base_point();
    SecureBuffer u = DhLadder::base_point();
    
    int the_ntests = (NTESTS < 1000000) ? 1000 : 1000000;
    
    /* EdDSA */
    if (eddsa_sk.size()) {
        SecureBuffer eddsa_pk2 = EdDSA::generate_key(eddsa_sk);
        if (!memeq(SecureBuffer(eddsa_pk), eddsa_pk2)) {
            test.fail();
            printf("    EdDSA PK vectors disagree.");
            printf("\n    Correct:   ");
            for (unsigned i=0; i<eddsa_pk.size(); i++) printf("%02x", eddsa_pk[i]);
            printf("\n    Incorrect: ");

            for (unsigned i=0; i<eddsa_pk2.size(); i++) printf("%02x", eddsa_pk2[i]);
            printf("\n");
        }
        SecureBuffer sig = EdDSA::sign(eddsa_sk,eddsa_pk,Block(NULL,0));

        if (!memeq(SecureBuffer(eddsa_sig0),sig)) {
            test.fail();
            printf("    EdDSA sig vectors disagree.");
            printf("\n    Correct:   ");
            for (unsigned i=0; i<eddsa_sig0.size(); i++) printf("%02x", eddsa_sig0[i]);
            printf("\n    Incorrect: ");

            for (unsigned i=0; i<sig.size(); i++) printf("%02x", sig[i]);
            printf("\n");
        }
    }
    
    /* X25519/X448 */
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

static void test_eddsa() {
    Test test("EdDSA");
    SpongeRng rng(Block("test_eddsa"),SpongeRng::DETERMINISTIC);
    
    for (int i=0; i<NTESTS && test.passing_now; i++) {
        
        FixedArrayBuffer<EdDSA::PRIVATE_BYTES> priv(rng);
        SecureBuffer pub = EdDSA::generate_key(priv);
        
        SecureBuffer message(i);
        rng.read(message);
        
        SecureBuffer context(EdDSA::SUPPORTS_CONTEXTS ? i%256 : 0);
        rng.read(message);
        
        SecureBuffer sig = EdDSA::sign(priv,pub,message,i%2,context); 
        
        try {
            EdDSA::verify(sig,pub,message,i%2,context); 
        } catch(CryptoException) {
            test.fail();
            printf("    Signature validation failed on sig %d\n", i);
        }    
    }
    
}

static void run() {
    printf("Testing %s:\n",Group::name());
    test_arithmetic();
    test_elligator();
    test_ec();
    test_eddsa();
    test_cfrg_crypto();
    test_cfrg_vectors();
    test_crypto();
    printf("\n");
}

}; /* template<GroupId GROUP> struct Tests */

/* X25519, X448 test vectors */
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

template<> const Block Tests<Ed448Goldilocks>::sqrt_minus_one(NULL,0);
const uint8_t sm1_25519[32] = {
    0xb0,0xa0,0x0e,0x4a,0x27,0x1b,0xee,0xc4,
    0x78,0xe4,0x2f,0xad,0x06,0x18,0x43,0x2f,
    0xa7,0xd7,0xfb,0x3d,0x99,0x00,0x4d,0x2b,
    0x0b,0xdf,0xc1,0x4f,0x80,0x24,0x83,0x2b
};
template<> const Block Tests<IsoEd25519>::sqrt_minus_one(sm1_25519,32);

template<> const Block Tests<Ed448Goldilocks>::minus_sqrt_minus_one(NULL,0);
const uint8_t msm1_25519[32] = {
    0x3d,0x5f,0xf1,0xb5,0xd8,0xe4,0x11,0x3b,
    0x87,0x1b,0xd0,0x52,0xf9,0xe7,0xbc,0xd0,
    0x58,0x28,0x04,0xc2,0x66,0xff,0xb2,0xd4,
    0xf4,0x20,0x3e,0xb0,0x7f,0xdb,0x7c,0x54
};
template<> const Block Tests<IsoEd25519>::minus_sqrt_minus_one(msm1_25519,32);

const uint8_t elli_patho_448[56] = {
    0x14,0xf0,0x70,0x58,0x41,0xc7,0xf9,0xa5,
    0xfa,0x2c,0x7d,0x87,0x07,0x89,0xe8,0x61,
    0x63,0xe8,0xc8,0xdc,0x06,0x2d,0x39,0x8f,
    0x18,0x83,0x1e,0xc6,0x8c,0x6d,0x73,0x24,
    0xd4,0xb3,0xd3,0xe1,0xf3,0x51,0x8c,0xee,
    0x65,0x79,0x88,0xc1,0x0b,0xcf,0x8e,0xa5,
    0x86,0xa9,0x2e,0xc9,0x17,0x68,0x9b,0x20
};
template<> const Block Tests<Ed448Goldilocks>::elli_patho(elli_patho_448,56);
template<> const Block Tests<IsoEd25519>::elli_patho(NULL,0);

/* EdDSA test vectors */
const uint8_t ed448_eddsa_sk[57] = {
    0x6c,0x82,0xa5,0x62,0xcb,0x80,0x8d,0x10,
    0xd6,0x32,0xbe,0x89,0xc8,0x51,0x3e,0xbf,
    0x6c,0x92,0x9f,0x34,0xdd,0xfa,0x8c,0x9f,
    0x63,0xc9,0x96,0x0e,0xf6,0xe3,0x48,0xa3,
    0x52,0x8c,0x8a,0x3f,0xcc,0x2f,0x04,0x4e,
    0x39,0xa3,0xfc,0x5b,0x94,0x49,0x2f,0x8f,
    0x03,0x2e,0x75,0x49,0xa2,0x00,0x98,0xf9,
    0x5b
};
const uint8_t ed448_eddsa_pk[57] = {
    0x5f,0xd7,0x44,0x9b,0x59,0xb4,0x61,0xfd,
    0x2c,0xe7,0x87,0xec,0x61,0x6a,0xd4,0x6a,
    0x1d,0xa1,0x34,0x24,0x85,0xa7,0x0e,0x1f,
    0x8a,0x0e,0xa7,0x5d,0x80,0xe9,0x67,0x78,
    0xed,0xf1,0x24,0x76,0x9b,0x46,0xc7,0x06,
    0x1b,0xd6,0x78,0x3d,0xf1,0xe5,0x0f,0x6c,
    0xd1,0xfa,0x1a,0xbe,0xaf,0xe8,0x25,0x61,
    0x80
};
const uint8_t ed448_eddsa_sig0[114] = {
    0x53,0x3a,0x37,0xf6,0xbb,0xe4,0x57,0x25,
    0x1f,0x02,0x3c,0x0d,0x88,0xf9,0x76,0xae,
    0x2d,0xfb,0x50,0x4a,0x84,0x3e,0x34,0xd2,
    0x07,0x4f,0xd8,0x23,0xd4,0x1a,0x59,0x1f,
    0x2b,0x23,0x3f,0x03,0x4f,0x62,0x82,0x81,
    0xf2,0xfd,0x7a,0x22,0xdd,0xd4,0x7d,0x78,
    0x28,0xc5,0x9b,0xd0,0xa2,0x1b,0xfd,0x39, 
    0x80,0xff,0x0d,0x20,0x28,0xd4,0xb1,0x8a,
    0x9d,0xf6,0x3e,0x00,0x6c,0x5d,0x1c,0x2d,
    0x34,0x5b,0x92,0x5d,0x8d,0xc0,0x0b,0x41,
    0x04,0x85,0x2d,0xb9,0x9a,0xc5,0xc7,0xcd,
    0xda,0x85,0x30,0xa1,0x13,0xa0,0xf4,0xdb,
    0xb6,0x11,0x49,0xf0,0x5a,0x73,0x63,0x26,
    0x8c,0x71,0xd9,0x58,0x08,0xff,0x2e,0x65,
    0x26,0x00
};
template<> const Block Tests<Ed448Goldilocks>::eddsa_sk(ed448_eddsa_sk,57);
template<> const Block Tests<Ed448Goldilocks>::eddsa_pk(ed448_eddsa_pk,57);
template<> const Block Tests<Ed448Goldilocks>::eddsa_sig0(ed448_eddsa_sig0,114);

const uint8_t ed25519_eddsa_sk[32] = {
    0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
    0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,
    0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,
    0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60
};
const uint8_t ed25519_eddsa_pk[32] = {
    0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,
    0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
    0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,
    0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
};
const uint8_t ed25518_eddsa_sig0[64] = {
    0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,
    0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
    0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,
    0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
    0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,
    0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
    0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,
    0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
};

template<> const Block Tests<IsoEd25519>::eddsa_sk(ed25519_eddsa_sk,32);
template<> const Block Tests<IsoEd25519>::eddsa_pk(ed25519_eddsa_pk,32);
template<> const Block Tests<IsoEd25519>::eddsa_sig0(ed25518_eddsa_sig0,64);

int main(int argc, char **argv) {
    (void) argc; (void) argv;
    run_for_all_curves<Tests>();
    if (passing) printf("Passed all tests.\n");
    return passing ? 0 : 1;
}
