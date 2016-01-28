field_data = {
    "p25519" : {
        "gf_desc" : "2^255 - 19",
        "gf_shortname" : "25519",
        "gf_impl_bits" : 320,
        "gf_lit_limb_bits" : 51
    },
    "p448" : {
        "gf_desc" : "2^448 - 2^224 - 1",
        "gf_shortname" : "448",
        "gf_impl_bits" : 512,
        "gf_lit_limb_bits" : 56
    }
}

curve_data = {
    "Curve25519" : {
        "iso_to" : "Curve25519",
        "name" : "Iso-Ed25519",
        "cofactor" : 8,
        "field" : "p25519",
        "scalar_bits" : 253,
        "d": -121665,
        "trace": -0xa6f7cef517bce6b2c09318d2e7ae9f7a,
        "mont_base": 9
    },
    "Ed448" : {
        "name" : "Ed448-Goldilocks",
        "cofactor" : 4,
        "field" : "p448",
        "scalar_bits" : 446,
        "d": -39081,
        "trace": 0x10cd77058eec492d944a725bf7a4cf635c8e9c2ab721cf5b5529eec34,
        "mont_base": 5
    }
}

def ser(x,bits,paren=None):
    out = ""
    mask = 2**bits - 1
    first = True
    while x > 0 or first:
        desc = "0x%0*x" % ((bits+3)//4,x&mask)
        if paren is not None:
            desc = "%s(%s)" % (paren,desc)
        if not first: out += ", "
        out += desc
        x = x >> bits
        first = False
    return out

def msqrt(x,p,hi_bit_clear = True):
    if p % 4 == 3: ret = pow(x,(p+1)//4,p)
    elif p % 8 == 5:
        for u in xrange(1,1000):
            if pow(u,(p-1)//2,p) != 1: break
        u = pow(u,(p-1)//4,p)
        ret = pow(x,(p+3)//8,p)
        if pow(ret,2,p) != (x % p): ret = (ret * u) % p
    else: raise Exception("sqrt only for 3-mod-4 or 5-mod-8")
        
    if (ret**2-x) % p != 0: raise Exception("No sqrt")
    if hi_bit_clear and ret > p//2: ret = p-ret
    return ret
        
def ceil_log2(x):
    out = 0
    cmp = 1
    while x > cmp:
        cmp = cmp<<1
        out += 1
    return out

for field,data in field_data.iteritems():
    if "modulus" not in data:
        data["modulus"] = eval(data["gf_desc"].replace("^","**"))
        
    data["p_mod_8"] = data["modulus"] % 8
    
    if "gf_bits" not in data:
        data["gf_bits"] = ceil_log2(data["modulus"])
        
    if "x_pub_bytes" not in data:
        data["x_pub_bytes"] = (data["gf_bits"]-1)//8 + 1
        
    if "x_priv_bytes" not in data:
        data["x_priv_bytes"] = (data["gf_bits"]-1)//8 + 1
        
    if "x_priv_bits" not in data:
        data["x_priv_bits"] = ceil_log2(data["modulus"]*0.99) # not per curve at least in 7748
        
    data["ser_modulus"] = ser(data["modulus"], data["gf_lit_limb_bits"])
    if data["modulus"] % 4 == 1: data["sqrt_minus_one"] = ser(msqrt(-1,data["modulus"]), data["gf_lit_limb_bits"])
    else: data["sqrt_minus_one"] = "/* NONE */"

for curve,data in curve_data.iteritems():
    for key in field_data[data["field"]]:
        if key not in data:
            data[key] = field_data[data["field"]][key]

        
    if "iso_to" not in data:
        data["iso_to"] = data["name"]
    
    if "cxx_ns" not in data:
        data["cxx_ns"] = data["name"].replace("-","")
    
    if "c_filename" not in data:
        data["c_filename"] = data["iso_to"].replace("-","").lower()
    
    mod = data["modulus"]
    ptwo = 2
    while mod % ptwo == 1:
        ptwo *= 2
    data["modulus_type"] = mod % ptwo

    if "imagine_twist" not in data:
        if data["modulus_type"] == 3: data["imagine_twist"] = 0
        else: data["imagine_twist"] = 1

    data["q"] = (data["modulus"]+1-data["trace"]) // data["cofactor"]
    data["bits"] = ceil_log2(data["modulus"])
    data["decaf_base"] = ser(msqrt(data["mont_base"],data["modulus"]),8)
    data["scalar_p"] = ser(data["q"],64,"SC_LIMB")
    
    if data["cofactor"] > 4: data["sqrt_one_minus_d"] = ser(msqrt(1-data["d"],data["modulus"]),data["gf_lit_limb_bits"])
    else: data["sqrt_one_minus_d"] = "/* NONE */"
    
    if "shortname" not in data:
        data["shortname"] = str(data["bits"])
    
    if "c_ns" not in data:
        data["c_ns"] = "decaf_" + data["shortname"]
        data["C_NS"] = data["c_ns"].upper()
        
    data["ser_bytes"] = (data["bits"]-2)//8 + 1 # TODO: split for decaf vs non-decaf
    data["scalar_ser_bytes"] = (data["scalar_bits"]-1)//8 + 1
    
