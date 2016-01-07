curve_data = {
    "Curve25519" : {
        "iso_to" : "Curve25519",
        "name" : "IsoEd25519",
        "cxx_ns" : "IsoEd25519",
        "shortname" : "255",
        "longnum" : "25519",
        "c_ns" : "decaf_255",
        "cofactor" : 8,
        "modulus" : 2**255 - 19,
        "scalar_bits" : 253,
        "gf_bits" : 320
    },
    "Ed448" : {
        "iso_to" : "Ed448-Goldilocks",
        "name" : "Ed448-Goldilocks",
        "cxx_ns" : "Ed448Goldilocks",
        "shortname" : "448",
        "longnum" : "448",
        "c_ns" : "decaf_448",
        "cofactor" : 4,
        "modulus" : 2**448 - 2**224 - 1,
        "scalar_bits" : 446,
        "gf_bits" : 512
    }
}

def ceil_log2(x):
    out = 0
    cmp = 1
    while x > cmp:
        cmp = cmp<<1
        out += 1
    return out

for curve,data in curve_data.iteritems():
    if "modulus_type" not in data:
        mod = data["modulus"]
        ptwo = 2
        while mod % ptwo == 1:
            ptwo *= 2
        data["modulus_type"] = mod % ptwo
    
    if "bits" not in data:
        data["bits"] = ceil_log2(data["modulus"])
        
    if "ser_bytes" not in data:
        data["ser_bytes"] = (data["bits"]-1)//8 + 1
    
    if "scalar_ser_bytes" not in data:
        data["scalar_ser_bytes"] = (data["scalar_bits"]-1)//8 + 1
    
    if "C_NS" not in data:
        data["C_NS"] = data["c_ns"].upper()

