from gen_file import gen_file,gend_files

import os
import argparse
import re

parser = argparse.ArgumentParser(description='Generate Decaf headers and other such files.')
parser.add_argument('--hpre', required = True, help = "Where to put the public header files")
parser.add_argument('--ihpre', required = True, help = "Where to put the internal header files")
parser.add_argument('--cpre', required = True, help = "Where to put the C/C++ implementation files")
args = parser.parse_args()

prefixes = { (True,"h") : args.hpre, (True,"hxx") : args.hpre, (False,"c") : args.cpre, (False,"h") : args.ihpre }

from decaf_hxx import decaf_hxx
from decaf_h import decaf_h
from crypto_h import crypto_h
from crypto_hxx import crypto_hxx
from f_field_h import f_field_h
from curve_data import curve_data
from curve_data_inc_c import curve_data_inc_c

root_hxx_code = "\n".join((
    "#include <%s>" % name
    for name in sorted(gend_files)
    if re.match("^decaf/decaf_\d+.hxx$",name)
))
root_hxx_code += """

namespace decaf {
    template <template<typename Group> class Run>
    void run_for_all_curves() {
"""
root_hxx_code += "\n".join((
    "        Run<%s>::run();" % cd["cxx_ns"]
    for cd in sorted(curve_data.values(), key=lambda x:x["c_ns"])
))
root_hxx_code += """
    }
}
"""
decaf_root_hxx = gen_file(
    public = True,
    per = "global",
    name = "decaf.hxx",
    doc = """@brief Decaf curve metaheader.""",
    code = "\n"+root_hxx_code+"\n"
)

crypto_h_code = "\n".join((
    "#include <%s>" % name
    for name in sorted(gend_files)
    if re.match("^decaf/crypto_\d+.h$",name)
))
crypto_h = gen_file(
    public = True,
    per = "global",
    name = "decaf/crypto.h",
    doc = """
        Example Decaf crypto routines, metaheader.
        @warning These are merely examples, though they ought to be secure.  But real
        protocols will decide differently on magic numbers, formats, which items to
        hash, etc.
    """,
    code = "\n"+crypto_h_code+"\n"
)

crypto_hxx_code = "\n".join((
    "#include <%s>" % name
    for name in sorted(gend_files)
    if re.match("^decaf/crypto_\d+.hxx$",name)
))
crypto_hxx = gen_file(
    public = True,
    per = "global",
    name = "decaf/crypto.hxx",
    doc = """
        Example Decaf crypto routines, C++, metaheader.
        @warning These are merely examples, though they ought to be secure.  But real
        protocols will decide differently on magic numbers, formats, which items to
        hash, etc.
    """,
    code = "\n"+crypto_hxx_code+"\n"
)

root_h_code = "\n".join((
    "#include <%s>" % name
    for name in sorted(gend_files)
    if re.match("^decaf/decaf_\d+.h$",name)
))
decaf_root_hxx = gen_file(
    public = True,
    per = "global",
    name = "decaf.h",
    doc = """
        Master header for Decaf library.
        
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


for name,(public,code) in gend_files.iteritems():        
    _,_,name_suffix = name.rpartition(".")
    prefix = prefixes[(public,name_suffix)]
    if not os.path.exists(os.path.dirname(prefix + "/" + name)):
        os.makedirs(os.path.dirname(prefix + "/" + name))
    with open(prefix + "/" + name,"w") as f:
        f.write(code + "\n")
    
    