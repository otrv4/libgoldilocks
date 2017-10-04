/**
 * @file ristretto.cxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Ristretto implementation widget
 */

#include <decaf.hxx>
#include <stdio.h>
using namespace decaf;

inline int hexi(char c) {
    if (c >= '0' && c < '9') return c-'0';
    if (c >= 'a' && c < 'f') return c-'a'+0xa;
    if (c >= 'A' && c < 'F') return c-'A'+0xa;
    return -1;
}

int parsehex(uint8_t *out, size_t sizeof_out, const char *hex) {
    size_t l = strlen(hex);
    if (l%2 != 0) {
        fprintf(stderr,"String should be hex, but has odd length\n: %s\n", hex);
        return -1;
    } else if (l/2 > sizeof_out) {
        fprintf(stderr,"Argument is too long: %s\n", hex);
        return -1;
    }
    
    memset(out,0,sizeof_out);
    int ret1,ret2;
    for (size_t i=0; i<l/2; i++) {
        if (   (ret1 = hexi(hex[2*i  ])) < 0
        || (ret2 = hexi(hex[2*i+1])) < 0) {
            fprintf(stderr,"Invalid hex %s\n",hex);
            return -1;
        }
        out[i] = ret1*16+ret2;
    }
    return 0;
}

void printhex(const uint8_t *in, size_t sizeof_in) {
    for (; sizeof_in > 0; in++,sizeof_in--) {
        printf("%02x",*in);
    }
}


static int g_argc = 0;
static char **g_argv = NULL;
static int error = 0;
static int done = 0;

void usage() {
    const char *me=g_argv[0];
    if (!me) me = "ristretto";
    for (unsigned i=0; g_argv[0][i]; i++) {
        if (g_argv[0][i] == '/' && g_argv[0][i+1] != 0 && g_argv[0][i+1] != '/') {
            me = &g_argv[0][i];
        }
    }
    
    fprintf(stderr,"Usage: %s [points] [operations] ...\n", me);
    fprintf(stderr,"  -b 255|448: Set which group to use (sometimes inferred from lengths)\n");
    fprintf(stderr,"\n");
    fprintf(stderr,"  Ways to create points:\n");
    fprintf(stderr,"    [hex]: Point from point data as hex\n");
    fprintf(stderr,"    -e [hex]: Create point by hashing to curve using elligator\n");
    fprintf(stderr,"    base: Base point of curve\n");
    fprintf(stderr,"\n");
    fprintf(stderr,"  Operations:\n");
    fprintf(stderr,"    -n [point]: negative of point\n");
    fprintf(stderr,"    -s [scalar] * [point]: Hash to curve using elligator\n");
    fprintf(stderr,"    [point] + [point]: Add two poitns\n");
    fprintf(stderr,"\n");
    fprintf(stderr,"  NB: this is a debugging widget.  It doesn't yet have order of operations.\n");
    fprintf(stderr,"  *** DON'T USE THIS UTILITY FOR ACTUAL CRYPTO! ***\n");
    fprintf(stderr,"  It's only for debugging!\n");
    fprintf(stderr,"\n");
    
    exit(-2);
}

template<typename Group> class Run {
public:
    static void run() {
        uint8_t tmp[Group::Point::SER_BYTES];
        typename Group::Point a,b;
        typename Group::Scalar s;
        bool plus=false, empty=true, elligator=false, mul=false, scalar=false, scalarempty=true, neg=false;
        if (done || error) return;
        for (int i=1; i<g_argc && !error; i++) {
            bool point = false;
            
            if (!strcmp(g_argv[i],"-b") && ++i<g_argc) {
                if (atoi(g_argv[i]) == Group::bits()) continue;
                else return;
            } else if (!strcmp(g_argv[i],"+")) {
                if (elligator || scalar || empty) usage();
                plus = true;
            } else if (!strcmp(g_argv[i],"-n")) {
                neg = !neg;
            } else if (!strcmp(g_argv[i],"*")) {
                if (elligator || scalar || scalarempty) usage();
                mul = true;
            } else if (!strcmp(g_argv[i],"-s")) {
                if (elligator || scalar || !scalarempty) usage();
                scalar = true;
            } else if (!strcmp(g_argv[i],"-e")) {
                if (elligator || scalar) usage();
                elligator = true;
            } else if (!strcmp(g_argv[i],"base")) {
                if (elligator || scalar) usage();
                b = b.base();
                point = true;
            } else if ((strlen(g_argv[i]) == 2*sizeof(tmp)
                    || ((scalar || elligator) && strlen(g_argv[i]) <= 2*sizeof(tmp)))
                        && !(error=parsehex(tmp,sizeof(tmp),g_argv[i]))) {
                if (scalar) {
                    s = Block(tmp,sizeof(tmp)); scalar=false; scalarempty=false;
                } else if (elligator) {
                    point = true;
                    b.set_to_hash(Block(tmp,sizeof(tmp))); elligator=false;
                } else if (DECAF_SUCCESS != b.decode(Block(tmp,sizeof(tmp)))) {
                    fprintf(stderr,"Error: %s isn't in the group\n",g_argv[i]);
                    error = -1;
                } else {
                    point = true;
                }
            } else if (error || !empty) usage();

            if (point) {
                if (neg) { b = -b; neg = false; }
                if (mul) { b *= s; mul=false; }
                if (empty) { a = b; empty=false; }
                else if (plus) { a += b; plus=false; }
                else usage();
            }
        }
        
        if (!error && !empty) {
            a.serialize_into(tmp);
            printhex(tmp,sizeof(tmp));
            printf("\n");
            done = true;
        }
        
    }
};

int main(int argc, char **argv) {
    g_argc = argc;
    g_argv = argv;
    run_for_all_curves<Run>();
    if (!done) usage();
    return (error<0) ? -error : error;
}
