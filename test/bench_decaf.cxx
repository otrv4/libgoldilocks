/**
 * @file test_decaf.cxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief C++ benchmarks, because that's easier.
 */

#include <decaf.hxx>
#include <decaf/shake.hxx>
#include <decaf/sha512.hxx>
#include <decaf/strobe.hxx>
#include <decaf/spongerng.hxx>
#include <decaf/crypto_255.h>
#include <decaf/crypto_448.h>
#include <decaf/crypto.hxx>
#include <decaf/eddsa.hxx>
#include <stdio.h>
#include <sys/time.h>
#include <assert.h>
#include <stdint.h>
#include <vector>
#include <algorithm>

using namespace decaf;
using namespace decaf::TOY;


static __inline__ void __attribute__((unused)) ignore_result ( int result ) { (void)result; }
static double now(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec/1000000.0;
}

// RDTSC from the chacha code
#ifndef __has_builtin
#define __has_builtin(X) 0
#endif
#if defined(__clang__) && __has_builtin(__builtin_readcyclecounter)
#define rdtsc __builtin_readcyclecounter
#else
static inline uint64_t rdtsc(void) {
# if defined(__x86_64__)
    uint32_t lobits, hibits;
    __asm__ __volatile__ ("rdtsc" : "=a"(lobits), "=d"(hibits));
    return (lobits | ((uint64_t)(hibits) << 32));
# elif defined(__i386__)
    uint64_t __value;
    __asm__ __volatile__ ("rdtsc" : "=A"(__value));
    return __value;
# else
    return 0;
# endif
}
#endif

static void printSI(double x, const char *unit, const char *spacer = " ") {
    const char *small[] = {" ","m","µ","n","p"};
    const char *big[] = {" ","k","M","G","T"};
    if (x < 1) {
        unsigned di=0;
        for (di=0; di<sizeof(small)/sizeof(*small)-1 && x && x < 1; di++) { 
            x *= 1000.0;
        }
        printf("%6.2f%s%s%s", x, spacer, small[di], unit);
    } else {
        unsigned di=0;
        for (di=0; di<sizeof(big)/sizeof(*big)-1 && x && x >= 1000; di++) { 
            x /= 1000.0;
        }
        printf("%6.2f%s%s%s", x, spacer, big[di], unit);
    }
}

class Benchmark {
    static const int NTESTS = 20, NSAMPLES=50, DISCARD=2;
    static double totalCy, totalS;
public:
    int i, j, ntests, nsamples;
    double begin;
    uint64_t tsc_begin;
    std::vector<double> times;
    std::vector<uint64_t> cycles;
    Benchmark(const char *s, double factor = 1) {
        printf("%s:", s);
        if (strlen(s) < 25) printf("%*s",int(25-strlen(s)),"");
        fflush(stdout);
        i = j = 0;
        ntests = NTESTS * factor;
        nsamples = NSAMPLES;
        begin = now();
        tsc_begin = rdtsc();
        times = std::vector<double>(NSAMPLES);
        cycles = std::vector<uint64_t>(NSAMPLES);
    }
    ~Benchmark() {
        double tsc = 0;
        double t = 0;
        
        std::sort(times.begin(), times.end());
        std::sort(cycles.begin(), cycles.end());
        
        for (int k=DISCARD; k<nsamples-DISCARD; k++) {
            tsc += cycles[k];
            t += times[k];
        }
        
        totalCy += tsc;
        totalS += t;
        
        t /= ntests*(nsamples-2*DISCARD);
        tsc /= ntests*(nsamples-2*DISCARD);
        
        printSI(t,"s");
        printf("    ");
        printSI(1/t,"/s");
        if (tsc) { printf("    "); printSI(tsc, "cy"); }
        printf("\n");
    }
    inline bool iter() {
        i++;
        if (i >= ntests) {
            uint64_t tsc = rdtsc() - tsc_begin;
            double t = now() - begin;
            begin += t;
            tsc_begin += tsc;
            assert(j >= 0 && j < nsamples);
            cycles[j] = tsc;
            times[j] = t;
            
            j++;
            i = 0;
        }
        return j < nsamples;
    }
    static void calib() {
        if (totalS && totalCy) {
            const char *s = "Cycle calibration";
            printf("%s:", s);
            if (strlen(s) < 25) printf("%*s",int(25-strlen(s)),"");
            printSI(totalCy / totalS, "Hz");
            printf("\n");
        }
    }
};

double Benchmark::totalCy = 0, Benchmark::totalS = 0;


template<typename Group> struct Benches {

typedef typename Group::Scalar Scalar;
typedef typename Group::Point Point;
typedef typename Group::Precomputed Precomputed;

static void tdh (
    SpongeRng &clientRng,
    SpongeRng &serverRng,
    Scalar x, const Block &gx,
    Scalar y, const Block &gy
) {
    /* "TripleDH".  A bit of a hack, really: the real TripleDH
     * sends gx and gy and certs over the channel, but its goal
     * is actually the opposite of STROBE in this case: it doesn't
     * hash gx and gy into the session secret (only into the MAC
     * and AD) because of IPR concerns.
     */
    Strobe client("example::tripleDH",Strobe::CLIENT), server("example::tripleDH",Strobe::SERVER);
    
    Scalar xe(clientRng);
    SecureBuffer gxe((Precomputed::base() * xe).serialize());
    client.send_plaintext(gxe);
    server.recv_plaintext(gxe);
    
    Scalar ye(serverRng);
    SecureBuffer gye((Precomputed::base() * ye).serialize());
    server.send_plaintext(gye);
    client.recv_plaintext(gye);
    
    Point pgxe(gxe);
    server.dh_key(pgxe*ye);
    SecureBuffer tag1 = server.produce_auth();
    //SecureBuffer ct = server.encrypt(gy);
    server.dh_key(pgxe*y);
    SecureBuffer tag2 = server.produce_auth();
    
    Point pgye(gye);
    client.dh_key(pgye*xe);
    client.verify_auth(tag1);
    client.dh_key(Point(gy) * xe);
    client.verify_auth(tag2);
    // ct = client.encrypt(gx);
    client.dh_key(pgye * x);
    tag1 = client.produce_auth();
    client.respec(STROBE_KEYED_128);
    
    server.dh_key(Point(gx) * ye);
    server.verify_auth(tag1);
    server.respec(STROBE_KEYED_128);
}

static void fhmqv (
    SpongeRng &clientRng,
    SpongeRng &serverRng,
    Scalar x, const Block &gx,
    Scalar y, const Block &gy
) {
    /* Don't use this, it's probably patented */
    Strobe client("example::fhmqv",Strobe::CLIENT), server("example::fhmqv",Strobe::SERVER);
    
    Scalar xe(clientRng);
    client.send_plaintext(gx);
    server.recv_plaintext(gx);
    SecureBuffer gxe((Precomputed::base() * xe).serialize());
    server.send_plaintext(gxe);
    client.recv_plaintext(gxe);

    Scalar ye(serverRng);
    server.send_plaintext(gy);
    client.recv_plaintext(gy);
    SecureBuffer gye((Precomputed::base() * ye).serialize());
    server.send_plaintext(gye);
    
    Scalar schx(server.prng(Scalar::SER_BYTES));
    Scalar schy(server.prng(Scalar::SER_BYTES));
    Scalar yec = y + ye*schy;
    server.dh_key(Point::double_scalarmul(Point(gx),yec,Point(gxe),yec*schx));
    SecureBuffer as = server.produce_auth();
    
    client.recv_plaintext(gye);
    Scalar cchx(client.prng(Scalar::SER_BYTES));
    Scalar cchy(client.prng(Scalar::SER_BYTES));
    Scalar xec = x + xe*schx;
    client.dh_key(Point::double_scalarmul(Point(gy),xec,Point(gye),xec*schy));
    client.verify_auth(as);
    SecureBuffer ac = client.produce_auth();
    client.respec(STROBE_KEYED_128);
    
    server.verify_auth(ac);
    server.respec(STROBE_KEYED_128);
}

static void spake2ee(
    SpongeRng &clientRng,
    SpongeRng &serverRng,
    const Block &hashed_password,
    bool aug
) {
    Strobe client("example::spake2ee",Strobe::CLIENT), server("example::spake2ee",Strobe::SERVER);
    
    Scalar x(clientRng);
    
    SHAKE<256> shake;
    shake.update(hashed_password);
    SecureBuffer h0 = shake.output(Point::HASH_BYTES);
    SecureBuffer h1 = shake.output(Point::HASH_BYTES);
    SecureBuffer h2 = shake.output(Scalar::SER_BYTES);
    Scalar gs(h2);
    
    Point hc = Point::from_hash(h0);
    hc = Point::from_hash(h0); // double-count
    Point hs = Point::from_hash(h1);
    hs = Point::from_hash(h1); // double-count
    
    SecureBuffer gx((Precomputed::base() * x + hc).serialize());
    client.send_plaintext(gx);
    server.recv_plaintext(gx);
    
    Scalar y(serverRng);
    SecureBuffer gy((Precomputed::base() * y + hs).serialize());
    server.send_plaintext(gy);
    client.recv_plaintext(gy);
    
    server.dh_key(h1);
    server.dh_key((Point(gx) - hc)*y);
    if(aug) {
        /* This step isn't actually online but whatever, it's fastish */
        SecureBuffer serverAug((Precomputed::base() * gs).serialize());
        server.dh_key(Point(serverAug)*y);
    }
    SecureBuffer tag = server.produce_auth();
    
    client.dh_key(h1);
    Point pgy(gy); pgy -= hs;
    client.dh_key(pgy*x);
    if (aug) client.dh_key(pgy * gs);
    client.verify_auth(tag);    
    tag = client.produce_auth();
    client.respec(STROBE_KEYED_128);
    /* A real protocol would continue with fork etc here... */
    
    server.verify_auth(tag);
    server.respec(STROBE_KEYED_128);
}

static void cfrg() {
    SpongeRng rng(Block("bench_cfrg_crypto"),SpongeRng::DETERMINISTIC);
    FixedArrayBuffer<Group::DhLadder::PUBLIC_BYTES> base(rng);
    FixedArrayBuffer<Group::DhLadder::PRIVATE_BYTES> s1(rng);
    for (Benchmark b("RFC 7748 keygen"); b.iter(); ) { Group::DhLadder::derive_public_key(s1); }
    for (Benchmark b("RFC 7748 shared secret"); b.iter(); ) { Group::DhLadder::shared_secret(base,s1); }

    FixedArrayBuffer<EdDSA<Group>::PrivateKey::SER_BYTES> e1(rng);
    typename EdDSA<Group>::PublicKey pub((NOINIT()));
    typename EdDSA<Group>::PrivateKey priv((NOINIT()));
    SecureBuffer sig;
    for (Benchmark b("EdDSA keygen"); b.iter(); ) { priv = e1; }
    for (Benchmark b("EdDSA sign"); b.iter(); ) { sig = priv.sign(Block(NULL,0)); }
    pub = priv;
    for (Benchmark b("EdDSA verify"); b.iter(); ) { pub.verify(sig,Block(NULL,0)); }
}

static void macro() {
    printf("\nMacro-benchmarks for %s:\n", Group::name());
    printf("CFRG crypto benchmarks:\n");
    cfrg();
    
    printf("\nToy crypto benchmarks:\n");
    SpongeRng rng(Block("macro rng seed"),SpongeRng::DETERMINISTIC);
    PrivateKey<Group> s1((NOINIT())), s2(rng);
    PublicKey<Group> p1((NOINIT())), p2(s2);

    SecureBuffer message = rng.read(5), sig, ss;

    for (Benchmark b("Create private key",1); b.iter(); ) {
        s1 = PrivateKey<Group>(rng);
        SecureBuffer bb = s1.serialize();
    }
    
    for (Benchmark b("Sign",1); b.iter(); ) {
        sig = s1.sign(message);
    }
    
    p1 = s1.pub();
    for (Benchmark b("Verify",1); b.iter(); ) {
        rng.read(Buffer(message));
        try { p1.verify(message, sig); } catch (CryptoException) {}
    }
    
    for (Benchmark b("SharedSecret",1); b.iter(); ) {
        ss = s1.shared_secret(p2,32,true);
    }
    
    printf("\nToy protocol benchmarks:\n");
    SpongeRng clientRng(Block("client rng seed"),SpongeRng::DETERMINISTIC);
    SpongeRng serverRng(Block("server rng seed"),SpongeRng::DETERMINISTIC);
    SecureBuffer hashedPassword(Block("hello world"));
    for (Benchmark b("Spake2ee c+s",0.1); b.iter(); ) {
        spake2ee(clientRng, serverRng, hashedPassword,false);
    }
    
    for (Benchmark b("Spake2ee c+s aug",0.1); b.iter(); ) {
        spake2ee(clientRng, serverRng, hashedPassword,true);
    }
    
    Scalar x(clientRng);
    SecureBuffer gx((Precomputed::base() * x).serialize());
    Scalar y(serverRng);
    SecureBuffer gy((Precomputed::base() * y).serialize());
    
    for (Benchmark b("FHMQV c+s",0.1); b.iter(); ) {
        fhmqv(clientRng, serverRng,x,gx,y,gy);
    }
    
    for (Benchmark b("TripleDH anon c+s",0.1); b.iter(); ) {
        tdh(clientRng, serverRng, x,gx,y,gy);
    }
}

static void micro() {
    SpongeRng rng(Block("per-curve-benchmarks"),SpongeRng::DETERMINISTIC);
    Precomputed pBase;
    Point p,q;
    Scalar s(1),t(2);
    SecureBuffer ep, ep2(Point::SER_BYTES*2);
    
    printf("\nMicro-benchmarks for %s:\n", Group::name());
    for (Benchmark b("Scalar add", 1000); b.iter(); ) { s+=t; }
    for (Benchmark b("Scalar times", 100); b.iter(); ) { s*=t; }
    for (Benchmark b("Scalar inv", 1); b.iter(); ) { s.inverse(); }
    for (Benchmark b("Point add", 100); b.iter(); ) { p += q; }
    for (Benchmark b("Point double", 100); b.iter(); ) { p.double_in_place(); }
    for (Benchmark b("Point scalarmul"); b.iter(); ) { p * s; }
    for (Benchmark b("Point encode"); b.iter(); ) { ep = p.serialize(); }
    for (Benchmark b("Point decode"); b.iter(); ) { p = Point(ep); }
    for (Benchmark b("Point create/destroy"); b.iter(); ) { Point r; }
    for (Benchmark b("Point hash nonuniform"); b.iter(); ) { Point::from_hash(ep); }
    for (Benchmark b("Point hash uniform"); b.iter(); ) { Point::from_hash(ep2); }
    for (Benchmark b("Point unhash nonuniform"); b.iter(); ) { ignore_result(p.invert_elligator(ep,0)); }
    for (Benchmark b("Point unhash uniform"); b.iter(); ) { ignore_result(p.invert_elligator(ep2,0)); }
    for (Benchmark b("Point steg"); b.iter(); ) { p.steg_encode(rng); }
    for (Benchmark b("Point double scalarmul"); b.iter(); ) { Point::double_scalarmul(p,s,q,t); }
    for (Benchmark b("Point dual scalarmul"); b.iter(); ) { p.dual_scalarmul(p,q,s,t); }
    for (Benchmark b("Point precmp scalarmul"); b.iter(); ) { pBase * s; }
    for (Benchmark b("Point double scalarmul_v"); b.iter(); ) {
        s = Scalar(rng);
        t = Scalar(rng);
        p.non_secret_combo_with_base(s,t);
    }
}

}; /* template <typename group> struct Benches */

template <typename Group> struct Macro { static void run() { Benches<Group>::macro(); } };
template <typename Group> struct Micro { static void run() { Benches<Group>::micro(); } };

int main(int argc, char **argv) {
    
    bool micro = false;
    if (argc >= 2 && !strcmp(argv[1], "--micro"))
        micro = true;

    SpongeRng rng(Block("micro-benchmarks"),SpongeRng::DETERMINISTIC);
    if (micro) {
        printf("\nMicro-benchmarks:\n");
        SHAKE<128> shake1;
        SHAKE<256> shake2;
        SHA3<512> sha5;
        SHA512 sha2;
        Strobe strobe("example::bench",Strobe::CLIENT);
        unsigned char b1024[1024] = {1};
        for (Benchmark b("SHAKE128 1kiB", 30); b.iter(); ) { shake1 += Buffer(b1024,1024); }
        for (Benchmark b("SHAKE256 1kiB", 30); b.iter(); ) { shake2 += Buffer(b1024,1024); }
        for (Benchmark b("SHA3-512 1kiB", 30); b.iter(); ) { sha5 += Buffer(b1024,1024); }
        for (Benchmark b("SHA512 1kiB", 30); b.iter(); ) { sha2 += Buffer(b1024,1024); }
        strobe.dh_key(Buffer(b1024,1024));
        strobe.respec(STROBE_128);
        for (Benchmark b("STROBE128 1kiB", 10); b.iter(); ) {
            strobe.encrypt_no_auth(Buffer(b1024,1024),Buffer(b1024,1024));
        }
        strobe.respec(STROBE_256);
        for (Benchmark b("STROBE256 1kiB", 10); b.iter(); ) {
            strobe.encrypt_no_auth(Buffer(b1024,1024),Buffer(b1024,1024));
        }
        strobe.respec(STROBE_KEYED_128);
        for (Benchmark b("STROBEk128 1kiB", 10); b.iter(); ) {
            strobe.encrypt_no_auth(Buffer(b1024,1024),Buffer(b1024,1024));
        }
        strobe.respec(STROBE_KEYED_256);
        for (Benchmark b("STROBEk256 1kiB", 10); b.iter(); ) {
            strobe.encrypt_no_auth(Buffer(b1024,1024),Buffer(b1024,1024));
        }
        
        run_for_all_curves<Micro>();
    }
    
    run_for_all_curves<Macro>();
    
    printf("\n");
    Benchmark::calib();
    printf("\n");
    
    return 0;
}
