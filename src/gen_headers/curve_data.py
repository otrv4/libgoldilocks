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
        "scalar_bits" : 253
    },
    "Ed448" : {
        "name" : "Ed448-Goldilocks",
        "cofactor" : 4,
        "field" : "p448",
        "scalar_bits" : 446
    }
}

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
    
    if "gf_bits" not in data:
        data["gf_bits"] = ceil_log2(data["modulus"])
        
    if "x_pub_bytes" not in data:
        data["x_pub_bytes"] = (data["gf_bits"]-1)//8 + 1
        
    if "x_priv_bytes" not in data:
        data["x_priv_bytes"] = (data["gf_bits"]-1)//8 + 1
        
    if "x_priv_bits" not in data:
        data["x_priv_bits"] = ceil_log2(data["modulus"]*0.99)

for curve,data in curve_data.iteritems():
    for key in field_data[data["field"]]:
        if key not in data:
            data[key] = field_data[data["field"]][key]
    
    if "iso_to" not in data:
        data["iso_to"] = data["name"]
    
    if "cxx_ns" not in data:
        data["cxx_ns"] = data["name"].replace("-","")
    
    if "modulus_type" not in data:
        mod = data["modulus"]
        ptwo = 2
        while mod % ptwo == 1:
            ptwo *= 2
        data["modulus_type"] = mod % ptwo
    
    if "bits" not in data:
        data["bits"] = ceil_log2(data["modulus"])
    
    if "shortname" not in data:
        data["shortname"] = str(data["bits"])
    
    if "c_ns" not in data:
        data["c_ns"] = "decaf_" + data["shortname"]
        
    if "ser_bytes" not in data:
        data["ser_bytes"] = (data["bits"]-2)//8 + 1
    
    if "scalar_ser_bytes" not in data:
        data["scalar_ser_bytes"] = (data["scalar_bits"]-1)//8 + 1
    
    if "C_NS" not in data:
        data["C_NS"] = data["c_ns"].upper()

