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
#include <decaf/eddsa.hxx>
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

    for (unsigned int i=0; i<NTESTS/10 && (i<10 || test.passing_now); i++) {
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
        for (unsigned int j=0; j<(i&3); j++) ss = ss.debugging_torque();
        
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
        decaf_error_t error = r.decode_like_eddsa_and_ignore_cofactor_noexcept(
            p.mul_by_cofactor_and_encode_like_eddsa()
        );
        if (error != DECAF_SUCCESS) {
            test.fail();
            printf("    Decode like EdDSA failed.");
        }
        point_check(test,-q,q,r,i,0,q,r,"Encode like EdDSA round-trip");
        
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
            DhLadder::derive_public_key(s1)
        )) {
            test.fail();
            printf("    Public keys disagree on iteration %d.\n",i);
        }
    }
}

static const bool eddsa_prehashed[];
static const Block eddsa_sk[], eddsa_pk[], eddsa_message[], eddsa_context[], eddsa_sig[];

static void test_cfrg_vectors() {
    Test test("CFRG test vectors");
    SecureBuffer k = DhLadder::base_point();
    SecureBuffer u = DhLadder::base_point();
    
    int the_ntests = (NTESTS < 1000000) ? 1000 : 1000000;
    
    /* EdDSA */
    for (unsigned int t=0; eddsa_sk[t].size(); t++) {
        typename EdDSA<Group>::PrivateKey priv(eddsa_sk[t]);
        SecureBuffer eddsa_pk2 = priv.pub().serialize();
        if (!memeq(SecureBuffer(eddsa_pk[t]), eddsa_pk2)) {
            test.fail();
            printf("    EdDSA PK vectors disagree.");
            printf("\n    Correct:   ");
            for (unsigned i=0; i<eddsa_pk[t].size(); i++) printf("%02x", eddsa_pk[t][i]);
            printf("\n    Incorrect: ");

            for (unsigned i=0; i<eddsa_pk2.size(); i++) printf("%02x", eddsa_pk2[i]);
            printf("\n");
        }
        SecureBuffer sig;
        
        if (eddsa_prehashed[t]) {
            typename EdDSA<Group>::PrivateKeyPh priv2(eddsa_sk[t]); 
            sig = priv2.sign_with_prehash(eddsa_message[t],eddsa_context[t]);
        } else {
            sig = priv.sign(eddsa_message[t],eddsa_context[t]);
        }

        if (!memeq(SecureBuffer(eddsa_sig[t]),sig)) {
            test.fail();
            printf("    EdDSA sig vectors disagree.");
            printf("\n    Correct:   ");
            for (unsigned i=0; i<eddsa_sig[t].size(); i++) printf("%02x", eddsa_sig[t][i]);
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
        
        typename EdDSA<Group>::PrivateKey priv(rng);
        typename EdDSA<Group>::PublicKey pub(priv);
        
        SecureBuffer message(i);
        rng.read(message);
        
        SecureBuffer context(i%256);
        rng.read(message);
        
        SecureBuffer sig = priv.sign(message,context); 
        
        try {
            pub.verify(sig,message,context); 
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
    printf("\n");
}

}; /* template<GroupId GROUP> struct Tests */

static void test_rng() {
    Test test("RNG");
    SpongeRng rng_d1(Block("test_rng"),SpongeRng::DETERMINISTIC);
    SpongeRng rng_d2(Block("test_rng"),SpongeRng::DETERMINISTIC);
    SpongeRng rng_d3(Block("best_rng"),SpongeRng::DETERMINISTIC);
    SpongeRng rng_n1;
    SpongeRng rng_n2;
    SecureBuffer s1,s2,s3;
    
    for (int i=0; i<5; i++) {
        s1 = rng_d1.read(16<<i);
        s2 = rng_d2.read(16<<i);
        s3 = rng_d3.read(16<<i);
        if (s1 != s2) {
            test.fail();
            printf("  Deterministic RNG didn't match!\n");
        }
        if (s1 == s3) {
            test.fail();
            printf("  Deterministic matched with different data!\n");
        }
        
        rng_d1.stir("hello");
        rng_d2.stir("hello");
        rng_d3.stir("hello");
        
        
        s1 = rng_n1.read(16<<i);
        s2 = rng_n2.read(16<<i);
        if (s1 == s2) {
            test.fail();
            printf("  Nondeterministic RNG matched!\n");
        }
    }
    
    
    rng_d1.stir("hello");
    rng_d2.stir("jello");
    s1 = rng_d1.read(16);
    s2 = rng_d2.read(16);
    if (s1 == s2) {
        test.fail();
        printf("  Deterministic matched with different data!\n");
    }
}

#include "vectors.inc.cxx"

int main(int argc, char **argv) {
    (void) argc; (void) argv;
    test_rng();
    printf("\n");
    run_for_all_curves<Tests>();
    if (passing) printf("Passed all tests.\n");
    return passing ? 0 : 1;
}
