/**
 * @cond internal
 * @file strobe.c
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief STROBE and spongerng instances.
 * @warning All APIs in here are toys.  They will change behavior and probably also API.
 * Do not use them for anything serious.
 */

#define __STDC_WANT_LIB_EXT1__ 1 /* for memset_s */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "keccak_internal.h"
#include <decaf/strobe.h>
#include <decaf/spongerng.h>

/* to open and read from /dev/urandom */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/** Get entropy from a CPU, preferably in the form of RDRAND, but possibly instead from RDTSC. */
static void get_cpu_entropy(uint8_t *entropy, size_t len) {
# if (defined(__i386__) || defined(__x86_64__))
    static char tested = 0, have_rdrand = 0;
    if (!tested) {
        uint32_t a,b,c,d;
        a=1; __asm__("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
        have_rdrand = (c>>30)&1;
        tested = 1;
    }

    if (have_rdrand) {
        # if defined(__x86_64__)
            uint64_t out, a=0, *eo = (uint64_t *)entropy;
        # elif defined(__i386__)
            uint32_t out, a=0, *eo = (uint32_t *)entropy;
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
#ifndef __has_builtin
#define __has_builtin(X) 0
#endif
#if defined(__clang__) && __has_builtin(__builtin_readcyclecounter)
        *(uint64_t*) entropy ^= __builtin_readcyclecounter();
#elif defined(__x86_64__)
        uint32_t lobits, hibits;
        __asm__ __volatile__ ("rdtsc" : "=a"(lobits), "=d"(hibits));
        *(uint64_t*) entropy ^= (lobits | ((uint64_t)(hibits) << 32));
#elif defined(__i386__)
        uint64_t __value;
        __asm__ __volatile__ ("rdtsc" : "=A"(__value));
        *(uint64_t*) entropy ^= __value;
#endif
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
        decaf_TOY_strobe_transact((keccak_decaf_TOY_strobe_s*)decaf_sponge,NULL,cpu_entropy,sizeof(cpu_entropy),STROBE_CW_PRNG_CPU_SEED);
    }
    
    decaf_TOY_strobe_transact((keccak_decaf_TOY_strobe_s*)decaf_sponge,out,NULL,len,STROBE_CW_PRNG);
}

void decaf_spongerng_stir (
    decaf_keccak_prng_t decaf_sponge,
    const uint8_t * __restrict__ in,
    size_t len
) {
    decaf_TOY_strobe_transact((keccak_decaf_TOY_strobe_s*)decaf_sponge,NULL,in,len,STROBE_CW_PRNG_USER_SEED);
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
    decaf_TOY_strobe_init((keccak_decaf_TOY_strobe_s*)decaf_sponge, &decaf_spongerng_params, SPONGERNG_NAME, !deterministic);
    decaf_spongerng_stir(prng, in, len);
}

decaf_error_t decaf_spongerng_init_from_file (
    decaf_keccak_prng_t prng,
    const char *file,
    size_t len,
    int deterministic
) {
    decaf_keccak_sponge_s *decaf_sponge = prng->sponge;
    decaf_TOY_strobe_init((keccak_decaf_TOY_strobe_s*)decaf_sponge, &decaf_spongerng_params, SPONGERNG_NAME, !deterministic);
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
        decaf_TOY_strobe_transact((keccak_decaf_TOY_strobe_s*)decaf_sponge,NULL,buffer,red,
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
void decaf_TOY_strobe_init(
    keccak_decaf_TOY_strobe_t strobe,
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
        
    decaf_TOY_strobe_transact(strobe,  NULL, (const unsigned char *)proto, strlen(proto), STROBE_CW_INIT);
        
    decaf_sponge->state->b[decaf_sponge->params->rate+1] = 1;
    decaf_sponge->params->client = !!am_client;
}

static const uint8_t EXCEEDED_RATE_PAD = 0x2;
static __inline__ uint8_t CONTROL_WORD_PAD(int cw_size) {
    assert(cw_size >= 0 && cw_size <= 31);
    return 0xC0 | cw_size;
}

/* PERF vectorize */
static void decaf_TOY_strobe_duplex (
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
        
        if (cando) {
        
            switch (mode) {
            case STROBE_MODE_PLAINTEXT:
                for (j=0; j<cando; j++) state[p+j] ^= in[j];
                if (out) {
                    assert(in != NULL);
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
                assert(in != NULL);
                memcpy(state+p, in, cando);
                in += cando;
                break;
        
            case STROBE_MODE_SQUEEZE:
                assert(out != NULL);
                memcpy(out, state+p, cando);
                out += cando;
                break;
        
            case STROBE_MODE_SQUEEZE_R:
                assert(out != NULL);
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
        }
        
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

void decaf_TOY_strobe_transact (
    keccak_decaf_TOY_strobe_t strobe,
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
        decaf_TOY_strobe_duplex(decaf_sponge, NULL, cwb, len_cw, STROBE_MODE_ABSORB_R);
        if ((cw_flags & STROBE_FLAG_RUN_F) || (decaf_sponge->params->flags & FLAG_NOPARSE)) {
            decaf_sponge->state->b[decaf_sponge->params->position] ^= CONTROL_WORD_PAD(len_cw);
            dokeccak(decaf_sponge);
        }

        decaf_sponge->params->flags &= ~FLAG_NOPARSE;
        if (cw_flags & STROBE_FLAG_NO_LENGTH) {
            decaf_sponge->params->flags |= FLAG_NOPARSE;
        }
    }
        
    decaf_TOY_strobe_duplex(decaf_sponge, out, in, len, get_mode(cw_flags));
    if (cw_flags & STROBE_FLAG_FORGET) {
        
        uint32_t len = decaf_sponge->params->rate - decaf_sponge->params->position;
        if (len < STROBE_FORGET_BYTES + len_cw) len += decaf_sponge->params->rate;
        len -= len_cw; /* HACK */
        
        if (cw_flags & STROBE_FLAG_NO_LENGTH) len = 2*STROBE_FORGET_BYTES;
        assert(!(cw_flags & STROBE_FLAG_MORE));
        
        decaf_TOY_strobe_duplex(
            decaf_sponge, NULL, NULL, len,
            STROBE_MODE_FORGET
        );
    }
}

decaf_error_t decaf_TOY_strobe_verify_auth (
    keccak_decaf_TOY_strobe_t strobe,
    const unsigned char *in,
    uint16_t len
) {
    decaf_keccak_sponge_s *decaf_sponge = strobe->sponge;
    if (len > decaf_sponge->params->rate) return DECAF_FAILURE;
    decaf_TOY_strobe_transact(strobe, NULL, in, len, decaf_TOY_strobe_cw_recv(STROBE_CW_MAC));
    
    int32_t residue = 0;
    int i;
    for (i=0; i<len; i++) {
        residue |= decaf_sponge->state->b[i];
    }
    
    return decaf_succeed_if((residue-1)>>8);
}

void decaf_TOY_strobe_respec (
    keccak_decaf_TOY_strobe_t strobe,
    const struct decaf_kparams_s *params
) {
    decaf_keccak_sponge_s *decaf_sponge = strobe->sponge;
    uint8_t in[] = { params->rate, params->start_round };
    decaf_TOY_strobe_transact( strobe, NULL, in, sizeof(in), STROBE_CW_RESPEC_INFO );
    decaf_TOY_strobe_transact( strobe, NULL, NULL, 0, STROBE_CW_RESPEC );
    assert(decaf_sponge->params->position == 0);
    decaf_sponge->params->rate = params->rate;
    decaf_sponge->params->start_round = params->start_round;
}
