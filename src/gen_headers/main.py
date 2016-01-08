from gen_file import gen_file,gend_files

import os
import argparse
import re

parser = argparse.ArgumentParser(description='Generate Decaf headers and other such files.')
parser.add_argument('--hpre', required = True, help = "Where to put the header files")
parser.add_argument('--cpre', required = True, help = "Where to put the C/C++ implementation files")
args = parser.parse_args()

prefixes = { "h" : args.hpre, "hxx" : args.hpre, "c" : args.cpre }

from decaf_hxx import decaf_hxx
from decaf_h import decaf_h
from crypto_h import crypto_h

root_hxx_code = "\n".join((
    "#include <%s>" % name
    for name in sorted(gend_files)
    if re.match("^decaf/decaf_\d+.hxx$",name)
))
decaf_root_hxx = gen_file(
    name = "decaf.hxx",
    doc = """@brief Decaf curve metaheader.""",
    code = "\n"+root_hxx_code+"\n"
)

root_h_code = "\n".join((
    "#include <%s>" % name
    for name in sorted(gend_files)
    if re.match("^decaf/decaf_\d+.h$",name)
))
decaf_root_hxx = gen_file(
    name = "decaf.h",
    doc = """
        @brief Master header for Decaf library.
        
        The Decaf library implements cryptographic operations on a elliptic curve
        groups of prime order p.  It accomplishes this by using a twisted Edwards
        curve (isogenous to Ed448-Goldilocks or Ed25519) and wiping out the cofactor.
        
        The formulas are all complete and have no special cases.  However, some
        functions can fail.  For example, decoding functions can fail because not
        every string is the encoding of a valid group element.
        
        The formulas contain no data-dependent branches, timing or memory accesses,
        except for decaf_XXX_base_double_scalarmul_non_secret.
    """,
    code = "\n"+root_h_code+"\n"
)


for name,code in gend_files.iteritems():        
    _,_,name_suffix = name.partition(".")
    prefix = prefixes[name_suffix]
    if not os.path.exists(os.path.dirname(prefix + "/" + name)):
        os.makedirs(os.path.dirname(prefix + "/" + name))
    with open(prefix + "/" + name,"w") as f:
        f.write(code + "\n")
    
    