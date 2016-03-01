/**
 * @cond internal
 * @file shake.c
 * @copyright
 *   Uses public domain code by Mathias Panzenböck \n
 *   Uses CC0 code by David Leon Gil, 2015 \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief SHA-3-n and SHAKE-n instances.
 * @warning EXPERIMENTAL!  The names, parameter orders etc are likely to change.
 */

#define __STDC_WANT_LIB_EXT1__ 1 /* for memset_s */
#define _BSD_SOURCE 1 /* for endian */
#include <assert.h>
#include <stdint.h>
#include <string.h>

/* to open and read from /dev/urandom */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* Subset of Mathias Panzenböck's portable endian code, public domain */
#if defined(__linux__) || defined(__CYGWIN__)
#	include <endian.h>
#elif defined(__OpenBSD__)
#	include <sys/endian.h>
#elif defined(__APPLE__)
#	include <libkern/OSByteOrder.h>
#	define htole64(x) OSSwapHostToLittleInt64(x)
#	define le64toh(x) OSSwapLittleToHostInt64(x)
#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#	include <sys/endian.h>
#	define le64toh(x) letoh64(x)
#elif defined(_WIN16) || defined(_WIN32) || defined(_WIN64) || defined(__WINDOWS__)
#	include <winsock2.h>
#	include <sys/param.h>
#	if BYTE_ORDER == LITTLE_ENDIAN
#		define htole64(x) (x)
#		define le64toh(x) (x)
#	elif BYTE_ORDER == BIG_ENDIAN
#		define htole64(x) __builtin_bswap64(x)
#		define le64toh(x) __builtin_bswap64(x)
#	else
#		error byte order not supported
#	endif
#else
#	error platform not supported
#endif

/* The internal, non-opaque definition of the decaf_sponge struct. */
typedef union {
    uint64_t w[25]; uint8_t b[25*8];
} kdomain_t[1];

typedef struct decaf_kparams_s {
    uint8_t position, flags, rate, start_round, pad, rate_pad, max_out, client; /* client = max_outRemaining for decaf_sha3 */
} decaf_kparams_t[1];

typedef struct decaf_keccak_sponge_s {
    kdomain_t state;
    decaf_kparams_t params;
} decaf_keccak_sponge_s, decaf_keccak_sponge_t[1];

#define INTERNAL_SPONGE_STRUCT 1
#include <decaf/shake.h>
#include <decaf/strobe.h>
#include <decaf/spongerng.h>

#define FLAG_ABSORBING 'A'
#define FLAG_SQUEEZING 'Z'

/** Constants. **/
static const uint8_t pi[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

#define RC_B(x,n) ((((x##ull)>>n)&1)<<((1<<n)-1))
#define RC_X(x) (RC_B(x,0)|RC_B(x,1)|RC_B(x,2)|RC_B(x,3)|RC_B(x,4)|RC_B(x,5)|RC_B(x,6))
static const uint64_t RC[24] = {
    RC_X(0x01), RC_X(0x1a), RC_X(0x5e), RC_X(0x70), RC_X(0x1f), RC_X(0x21),
    RC_X(0x79), RC_X(0x55), RC_X(0x0e), RC_X(0x0c), RC_X(0x35), RC_X(0x26),
    RC_X(0x3f), RC_X(0x4f), RC_X(0x5d), RC_X(0x53), RC_X(0x52), RC_X(0x48),
    RC_X(0x16), RC_X(0x66), RC_X(0x79), RC_X(0x58), RC_X(0x21), RC_X(0x74)
};

static inline uint64_t rol(uint64_t x, int s) {
    return (x << s) | (x >> (64 - s));
}

/* Helper macros to unroll the permutation. */
#define REPEAT5(e) e e e e e
#define FOR51(v, e) v = 0; REPEAT5(e; v += 1;)
#ifndef SHAKE_NO_UNROLL_LOOPS
#    define FOR55(v, e) v = 0; REPEAT5(e; v += 5;)
#    define REPEAT24(e) e e e e e e e e e e e e e e e e e e e e e e e e
#else
#    define FOR55(v, e) for (v=0; v<25; v+= 5) { e; }
#    define REPEAT24(e) {int _j=0; for (_j=0; _j<24; _j++) { e }}
#endif

/*** The Keccak-f[1600] permutation ***/
static void
__attribute__((noinline))
keccakf(kdomain_t state, uint8_t start_round) {
    uint64_t* a = state->w;
    uint64_t b[5] = {0}, t, u;
    uint8_t x, y, i;
    
    for (i=0; i<25; i++) a[i] = le64toh(a[i]);

    for (i = start_round; i < 24; i++) {
        FOR51(x, b[x] = 0; )
        FOR55(y, FOR51(x, b[x] ^= a[x + y]; ))
        FOR55(y, FOR51(x,
            a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1);
        ))
        // Rho and pi
        t = a[1];
        x = y = 0;
        REPEAT24(u = a[pi[x]]; y += x+1; a[pi[x]] = rol(t, y % 64); t = u; x++; )
        // Chi
        FOR55(y,
             FOR51(x, b[x] = a[y + x];)
             FOR51(x, a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);)
        )
        // Iota
        a[0] ^= RC[i];
    }

    for (i=0; i<25; i++) a[i] = htole64(a[i]);
}

static inline void dokeccak (decaf_keccak_sponge_t decaf_sponge) {
    keccakf(decaf_sponge->state, decaf_sponge->params->start_round);
    decaf_sponge->params->position = 0;
}

void decaf_sha3_update (
    struct decaf_keccak_sponge_s * __restrict__ decaf_sponge,
    const uint8_t *in,
    size_t len
) {
    if (!len) return;
    assert(decaf_sponge->params->position < decaf_sponge->params->rate);
    assert(decaf_sponge->params->rate < sizeof(decaf_sponge->state));
    assert(decaf_sponge->params->flags == FLAG_ABSORBING);
    while (len) {
        size_t cando = decaf_sponge->params->rate - decaf_sponge->params->position, i;
        uint8_t* state = &decaf_sponge->state->b[decaf_sponge->params->position];
        if (cando > len) {
            for (i = 0; i < len; i += 1) state[i] ^= in[i];
            decaf_sponge->params->position += len;
            return;
        } else {
            for (i = 0; i < cando; i += 1) state[i] ^= in[i];
            dokeccak(decaf_sponge);
            len -= cando;
            in += cando;
        }
    }
}

void decaf_sha3_output (
    decaf_keccak_sponge_t decaf_sponge,
    uint8_t * __restrict__ out,
    size_t len
) {
    assert(decaf_sponge->params->position < decaf_sponge->params->rate);
    assert(decaf_sponge->params->rate < sizeof(decaf_sponge->state));
    
    if (decaf_sponge->params->max_out != 0xFF) {
        assert(decaf_sponge->params->client >= len);
        decaf_sponge->params->client -= len;
    }
    
    switch (decaf_sponge->params->flags) {
    case FLAG_SQUEEZING: break;
    case FLAG_ABSORBING:
        {
            uint8_t* state = decaf_sponge->state->b;
            state[decaf_sponge->params->position] ^= decaf_sponge->params->pad;
            state[decaf_sponge->params->rate - 1] ^= decaf_sponge->params->rate_pad;
            dokeccak(decaf_sponge);
            break;
        }
    default:
        assert(0);
    }
    
    while (len) {
        size_t cando = decaf_sponge->params->rate - decaf_sponge->params->position;
        uint8_t* state = &decaf_sponge->state->b[decaf_sponge->params->position];
        if (cando > len) {
            memcpy(out, state, len);
            decaf_sponge->params->position += len;
            return;
        } else {
            memcpy(out, state, cando);
            dokeccak(decaf_sponge);
            len -= cando;
            out += cando;
        }
    }
}

void decaf_sha3_final (
    decaf_keccak_sponge_t decaf_sponge,
    uint8_t * __restrict__ out,
    size_t len
) {
    decaf_sha3_output(decaf_sponge,out,len);
    decaf_sha3_reset(decaf_sponge);
}

void decaf_sha3_reset (
    decaf_keccak_sponge_t decaf_sponge
) {
    decaf_sponge_init(decaf_sponge, decaf_sponge->params);
    decaf_sponge->params->client = decaf_sponge->params->max_out;
}

void decaf_sponge_destroy (decaf_keccak_sponge_t decaf_sponge) { decaf_bzero(decaf_sponge, sizeof(decaf_keccak_sponge_t)); }

void decaf_sponge_init (
    decaf_keccak_sponge_t decaf_sponge,
    const struct decaf_kparams_s *params
) {
    memset(decaf_sponge->state, 0, sizeof(decaf_sponge->state));
    decaf_sponge->params[0] = params[0];
    decaf_sponge->params->position = 0;
}

void decaf_sponge_hash (
    const uint8_t *in,
    size_t inlen,
    uint8_t *out,
    size_t outlen,
    const struct decaf_kparams_s *params
) {
    decaf_keccak_sponge_t decaf_sponge;
    decaf_sponge_init(decaf_sponge, params);
    decaf_sha3_update(decaf_sponge, in, inlen);
    decaf_sha3_output(decaf_sponge, out, outlen);
    decaf_sponge_destroy(decaf_sponge);
}

#define DEFSHAKE(n) \
    const struct decaf_kparams_s DECAF_SHAKE##n##_params_s = \
        { 0, FLAG_ABSORBING, 200-n/4, 0, 0x1f, 0x80, 0xFF, 0xFF };
    
#define DEFSHA3(n) \
    const struct decaf_kparams_s DECAF_SHA3_##n##_params_s = \
        { 0, FLAG_ABSORBING, 200-n/4, 0, 0x06, 0x80, n/8, n/8 };

size_t decaf_sponge_default_output_bytes (
    const decaf_keccak_sponge_t s
) {
    return (s->params->max_out == 0xFF)
        ? (200-s->params->rate)
        : ((200-s->params->rate)/2);
}

size_t decaf_sponge_max_output_bytes (
    const decaf_keccak_sponge_t s
) {
    return (s->params->max_out == 0xFF)
        ? SIZE_MAX
        : ((200-s->params->rate)/2);
}

DEFSHAKE(128)
DEFSHAKE(256)
DEFSHA3(224)
DEFSHA3(256)
DEFSHA3(384)
DEFSHA3(512)

/** Get entropy from a CPU, preferably in the form of RDRAND, but possibly instead from RDTSC. */
static void get_cpu_entropy(uint8_t *entropy, size_t len) {
# if (defined(__i386__) || defined(__x86_64__))
    static char tested = 0, have_rdrand = 0;
    if (!tested) {
        u_int32_t a,b,c,d;
        a=1; __asm__("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
        have_rdrand = (c>>30)&1;
        tested = 1;
    }

    if (have_rdrand) {
        # if defined(__x86_64__)
            uint64_t out, a=0, *eo = (uint64_t *)entropy;
        # elif defined(__i386__)
            uint32_t out, a=0, *eo = (uint64_t *)entropy;
        #endif
        len /= sizeof(out);

        uint32_t tries;
        for (tries = 100+len; tries && len; len--, eo++) {
            for (a = 0; tries && !a; tries--) {
                __asm__ __volatile__ ("rdrand %0\n\tsetc %%al" : "=r"(out), "+a"(a) :: "cc" );
            }
            *eo ^= out;
        }
    } else if (len>=8) {
        uint64_t out;
        __asm__ __volatile__ ("rdtsc" : "=A"(out));
        *(uint64_t*) entropy ^= out;
    }

#else
    (void) entropy;
    (void) len;
#endif
}

static const char *SPONGERNG_NAME = "strobe::decaf_spongerng";  /* TODO: canonicalize name */

void decaf_spongerng_next (
    decaf_keccak_prng_t prng,
    uint8_t * __restrict__ out,
    size_t len
) {
    decaf_keccak_sponge_s *decaf_sponge = prng->sponge;
    if (decaf_sponge->params->client) {
        /* nondet */
        uint8_t cpu_entropy[32];
        get_cpu_entropy(cpu_entropy, sizeof(cpu_entropy));
        strobe_transact((keccak_strobe_s*)decaf_sponge,NULL,cpu_entropy,sizeof(cpu_entropy),STROBE_CW_PRNG_CPU_SEED);
    }
    
    strobe_transact((keccak_strobe_s*)decaf_sponge,out,NULL,len,STROBE_CW_PRNG);
}

void decaf_spongerng_stir (
    decaf_keccak_prng_t decaf_sponge,
    const uint8_t * __restrict__ in,
    size_t len
) {
    strobe_transact((keccak_strobe_s*)decaf_sponge,NULL,in,len,STROBE_CW_PRNG_USER_SEED);
}

static const struct decaf_kparams_s decaf_spongerng_params = {
    0, 0, 200-256/4, 0, 0x06, 0x80, 0xFF, 0
};

void decaf_spongerng_init_from_buffer (
    decaf_keccak_prng_t prng,
    const uint8_t * __restrict__ in,
    size_t len,
    int deterministic
) {
    decaf_keccak_sponge_s *decaf_sponge = prng->sponge;
    strobe_init((keccak_strobe_s*)decaf_sponge, &decaf_spongerng_params, SPONGERNG_NAME, !deterministic);
    decaf_spongerng_stir(prng, in, len);
}

decaf_error_t decaf_spongerng_init_from_file (
    decaf_keccak_prng_t prng,
    const char *file,
    size_t len,
    int deterministic
) {
    decaf_keccak_sponge_s *decaf_sponge = prng->sponge;
    strobe_init((keccak_strobe_s*)decaf_sponge, &decaf_spongerng_params, SPONGERNG_NAME, !deterministic);
    if (!len) return DECAF_FAILURE;

    int fd = open(file, O_RDONLY);
    if (fd < 0) return DECAF_FAILURE;
    
    uint8_t buffer[128];
    int first = 1;
    while (len) {
        ssize_t red = read(fd, buffer, (len > sizeof(buffer)) ? sizeof(buffer) : len);
        if (red <= 0) {
            close(fd);
            return DECAF_FAILURE;
        }
        strobe_transact((keccak_strobe_s*)decaf_sponge,NULL,buffer,red,
            first ? STROBE_CW_PRNG_USER_SEED : (STROBE_CW_PRNG_USER_SEED | STROBE_FLAG_MORE));
        len -= red;
        first = 0;
    };
    close(fd);
    
    return DECAF_SUCCESS;
}

decaf_error_t decaf_spongerng_init_from_dev_urandom (
    decaf_keccak_prng_t decaf_sponge
) {
    return decaf_spongerng_init_from_file(decaf_sponge, "/dev/urandom", 64, 0);
}

const struct decaf_kparams_s STROBE_128 = { 0, 0, 200-128/4, 0, 0, 0, 0, 0 };
const struct decaf_kparams_s STROBE_256 = { 0, 0, 200-256/4, 0, 0, 0, 0, 0 };
const struct decaf_kparams_s STROBE_KEYED_256 = { 0, 0, 200-256/4, 12, 0, 0, 0, 0 };
const struct decaf_kparams_s STROBE_KEYED_128 = { 0, 0, 200-128/4, 12, 0, 0, 0, 0 };

/* Strobe is different in that its rate is padded by one byte. */
void strobe_init(
    keccak_strobe_t strobe,
    const struct decaf_kparams_s *params,
    const char *proto,
    uint8_t am_client
) {
    decaf_keccak_sponge_s *decaf_sponge = strobe->sponge;
    decaf_sponge_init(decaf_sponge,params);
    
    const char *a_string = "STROBE full v0.2";
    unsigned len = strlen(a_string);
    memcpy (
        &decaf_sponge->state->b[sizeof(decaf_sponge->state)-len],
        a_string,
        len
    );
        
    strobe_transact(strobe,  NULL, (const unsigned char *)proto, strlen(proto), STROBE_CW_INIT);
        
    decaf_sponge->state->b[decaf_sponge->params->rate+1] = 1;
    decaf_sponge->params->client = !!am_client;
}

static const uint8_t EXCEEDED_RATE_PAD = 0x2;
static __inline__ uint8_t CONTROL_WORD_PAD(int cw_size) {
    assert(cw_size >= 0 && cw_size <= 31);
    return 0xC0 | cw_size;
}

/* PERF vectorize */
static void strobe_duplex (
    struct decaf_keccak_sponge_s *__restrict__ decaf_sponge,
    unsigned char *out,
    const unsigned char *in,
    size_t len,
    mode_t mode
) {
    unsigned int j, r = decaf_sponge->params->rate, p = decaf_sponge->params->position;
    uint8_t* __restrict__ state = &decaf_sponge->state->b[0];
    
    /* sanity */
    assert(r < sizeof(decaf_sponge->state) && r >= p);
    switch (mode) {
    case STROBE_MODE_PLAINTEXT:
        assert(in || len==0);
        break;
    case STROBE_MODE_ABSORB:
    case STROBE_MODE_ABSORB_R:
        assert((in||len==0) && !out);
        break;
    case STROBE_MODE_DUPLEX:
    case STROBE_MODE_DUPLEX_R:
        assert((in && out) || len==0);
        break;
    case STROBE_MODE_SQUEEZE:
    case STROBE_MODE_SQUEEZE_R:
        assert((out || len==0) && !in);
        break;
    case STROBE_MODE_FORGET:
        assert(!in && !out);
        break;
    default:
        assert(0);
    }
    
    while(1) {
        unsigned int cando = r - p;
        unsigned int last = (cando >= len);
        if (last) {
            cando = len;
        }
        
        switch (mode) {
        case STROBE_MODE_PLAINTEXT:
            for (j=0; j<cando; j++) state[p+j] ^= in[j];
            if (out) {
                memcpy(out, in, cando);
                out += cando;
            }
            in += cando;
            break;
            
        case STROBE_MODE_ABSORB:
            for (j=0; j<cando; j++) state[p+j] ^= in[j];
            in += cando;
            break;
            
        case STROBE_MODE_ABSORB_R:
            memcpy(state+p, in, cando);
            in += cando;
            break;
        
        case STROBE_MODE_SQUEEZE:
            memcpy(out, state+p, cando);
            out += cando;
            break;
        
        case STROBE_MODE_SQUEEZE_R:
            memcpy(out, state+p, cando);
            out += cando;
            memset(state+p, 0, cando);
            break;
            
        case STROBE_MODE_FORGET:
            memset(state+p, 0, cando);
            break;
        
        case STROBE_MODE_DUPLEX:
            for (j=0; j<cando; j++) {
                state[p+j] ^= in[j];
                out[j] = state[p+j];
            }
            in += cando;
            out += cando;
            break;
        
        case STROBE_MODE_DUPLEX_R:
            for (j=0; j<cando; j++) {
                unsigned char c = in[j];
                out[j] = c ^ state[p+j];
                state[p+j] = c;
            }
            in += cando;
            out += cando;
            break;

        default:
            assert(0);
        };
        
        if (last) {
            decaf_sponge->params->position = p+len;
            return;
        } else {
            state[r] ^= EXCEEDED_RATE_PAD;
            keccakf(decaf_sponge->state, decaf_sponge->params->start_round);
            len -= cando;
            p = 0;
        }
    }
}

static inline mode_t get_mode ( uint32_t cw_flags ) {
    return (mode_t)((cw_flags >> 29) & 7);
}

static const int STROBE_FORGET_BYTES = 32;

static const uint8_t FLAG_NOPARSE = 1;

void strobe_transact (
    keccak_strobe_t strobe,
    unsigned char *out,
    const unsigned char *in,
    size_t len,
    uint32_t cw_flags
) {
    decaf_keccak_sponge_s *decaf_sponge = strobe->sponge;
    if ( (cw_flags & STROBE_FLAG_NONDIR) == 0
        /* extraneous nots to change ints to bools :-/ */
        && !(cw_flags & STROBE_FLAG_RECV) != !(decaf_sponge->params->client) ) {
        cw_flags ^= STROBE_FLAG_CLIENT_SENT;
    }
    
    uint64_t my_len = len, len_cw = (cw_flags & STROBE_FLAG_LENGTH_64) ? 10 : 4;
    if (cw_flags & STROBE_FLAG_NO_LENGTH) {
        my_len = 0;
    } else if ((cw_flags & STROBE_FLAG_LENGTH_64)==0) {
        assert(my_len < 1<<16);
    }
    
    if (cw_flags & STROBE_FLAG_MORE) {
        assert(cw_flags & STROBE_FLAG_NO_LENGTH); /* FUTURE */
    } else {
        uint8_t cwb[10] = {
            cw_flags,
            cw_flags>>8,
            my_len,
            my_len>>8,
            my_len>>16,
            my_len>>24,
            my_len>>32,
            my_len>>40,
            my_len>>48,
            my_len>>56
        };
        strobe_duplex(decaf_sponge, NULL, cwb, len_cw, STROBE_MODE_ABSORB_R);
        if ((cw_flags & STROBE_FLAG_RUN_F) || (decaf_sponge->params->flags & FLAG_NOPARSE)) {
            decaf_sponge->state->b[decaf_sponge->params->position] ^= CONTROL_WORD_PAD(len_cw);
            dokeccak(decaf_sponge);
        }

        decaf_sponge->params->flags &= ~FLAG_NOPARSE;
        if (cw_flags & STROBE_FLAG_NO_LENGTH) {
            decaf_sponge->params->flags |= FLAG_NOPARSE;
        }
    }
        
    strobe_duplex(decaf_sponge, out, in, len, get_mode(cw_flags));
    if (cw_flags & STROBE_FLAG_FORGET) {
        
        uint32_t len = decaf_sponge->params->rate - decaf_sponge->params->position;
        if (len < STROBE_FORGET_BYTES + len_cw) len += decaf_sponge->params->rate;
        len -= len_cw; /* HACK */
        
        if (cw_flags & STROBE_FLAG_NO_LENGTH) len = 2*STROBE_FORGET_BYTES;
        assert(!(cw_flags & STROBE_FLAG_MORE));
        
        strobe_duplex(
            decaf_sponge, NULL, NULL, len,
            STROBE_MODE_FORGET
        );
    }
}

decaf_error_t strobe_verify_auth (
    keccak_strobe_t strobe,
    const unsigned char *in,
    uint16_t len
) {
    decaf_keccak_sponge_s *decaf_sponge = strobe->sponge;
    if (len > decaf_sponge->params->rate) return DECAF_FAILURE;
    strobe_transact(strobe, NULL, in, len, strobe_cw_recv(STROBE_CW_MAC));
    
    int32_t residue = 0;
    int i;
    for (i=0; i<len; i++) {
        residue |= decaf_sponge->state->b[i];
    }
    
    return decaf_succeed_if((residue-1)>>8);
}

void strobe_respec (
    keccak_strobe_t strobe,
    const struct decaf_kparams_s *params
) {
    decaf_keccak_sponge_s *decaf_sponge = strobe->sponge;
    uint8_t in[] = { params->rate, params->start_round };
    strobe_transact( strobe, NULL, in, sizeof(in), STROBE_CW_RESPEC_INFO );
    strobe_transact( strobe, NULL, NULL, 0, STROBE_CW_RESPEC );
    assert(decaf_sponge->params->position == 0);
    decaf_sponge->params->rate = params->rate;
    decaf_sponge->params->start_round = params->start_round;
}

/* FUTURE: Keyak instances, etc */
