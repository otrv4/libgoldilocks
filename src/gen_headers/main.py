from gen_file import gend_files

import os
import argparse

parser = argparse.ArgumentParser(description='Generate Decaf headers and other such files.')
parser.add_argument('--hpre', required = True, help = "Where to put the header files")
parser.add_argument('--cpre', required = True, help = "Where to put the C/C++ implementation files")
args = parser.parse_args()

prefixes = { "h" : args.hpre, "hxx" : args.hpre, "c" : args.cpre }

from decaf_hxx import decaf_hxx
from decaf_h import decaf_h
from crypto_h import crypto_h

for name,code in gend_files.iteritems():        
    _,_,name_suffix = name.partition(".")
    prefix = prefixes[name_suffix]
    if not os.path.exists(os.path.dirname(prefix + "/" + name)):
        os.makedirs(os.path.dirname(prefix + "/" + name))
    with open(prefix + "/" + name,"w") as f:
        f.write(code + "\n")
    
    