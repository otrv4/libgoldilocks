from collections import namedtuple
from binascii import unhexlify

comb_config = namedtuple("comb_config",["n","t","s"])
wnaf_config = namedtuple("wnaf_config",["fixed","var"])

field_data = {
    "p448" : {
        "gf_desc" : "2^448 - 2^224 - 1",
        "gf_impl_bits" : 512,
        "gf_lit_limb_bits" : 56,
        "elligator_onto" : 0
    }
}

curve_data = {
    "ed448goldilocks" : {
        "eddsa_encode_ratio": 4,
        "x_encode_ratio": 2,
        "altname": None,
        "name" : "Ed448-Goldilocks",
        "cofactor" : 4,
        "field" : "p448",
        "scalar_bits" : 446,
        "d": -39081,
        "trace": 0x10cd77058eec492d944a725bf7a4cf635c8e9c2ab721cf5b5529eec34,
        "rist_base": "6666666666666666666666666666666666666666666666666666666633333333333333333333333333333333333333333333333333333333",
        "mont_base": 5,

        "combs":comb_config(5,5,18),
        "wnaf":wnaf_config(5,3),
        "window_bits":5,

        "eddsa_dom":"SigEd448"
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

def msqrt(x,p,hi_bit_clear = True, lo_bit_clear = False):
    if p % 4 == 3: ret = pow(x,(p+1)//4,p)
    elif p % 8 == 5:
        for u in range(1,1000):
            if pow(u,(p-1)//2,p) != 1: break
        u = pow(u,(p-1)//4,p)
        ret = pow(x,(p+3)//8,p)
        if pow(ret,2,p) != (x % p): ret = (ret * u) % p
    else: raise Exception("sqrt only for 3-mod-4 or 5-mod-8")

    if (ret**2-x) % p != 0: raise Exception("No sqrt")
    if hi_bit_clear and ret > p//2: ret = p-ret
    # lo_bit_clear overrides hi_bit_clear because it's not default
    if lo_bit_clear and (ret & 1): ret = p-ret
    return ret

def ceil_log2(x):
    out = 0
    cmp = 1
    while x > cmp:
        cmp = cmp<<1
        out += 1
    return out

for field,data in field_data.items():
    if "modulus" not in data:
        data["modulus"] = eval(data["gf_desc"].replace("^","**"))

    if "gf_bits" not in data:
        data["gf_bits"] = ceil_log2(data["modulus"])

for curve,data in curve_data.items():
    for key in field_data[data["field"]]:
        if key not in data:
            data[key] = field_data[data["field"]][key]


    if "iso_to" not in data:
        data["iso_to"] = data["name"]

    if "eddsa_hash" not in data:
        data["eddsa_hash"] = "shake256"

    if "eddsa_no_context" not in data:
        data["eddsa_no_context"] = 0

    if "cxx_ns" not in data:
        data["cxx_ns"] = data["name"].replace("-","")

    if "eddsa_sigma_iso" not in data:
        data["eddsa_sigma_iso"] = 0

    if "rist_base_decoded" not in data:
        def xord(x):
            if isinstance(x,str): return ord(x)
            else: return x
        data["rist_base_decoded"] = sum(
                xord(b)<<(8*i) for i,b in enumerate(unhexlify(data["rist_base"]))
            )

    if "imagine_twist" not in data:
        data["imagine_twist"] = 0

    data["q"] = (data["modulus"]+1-data["trace"]) // data["cofactor"]
    data["bits"] = ceil_log2(data["modulus"])

    if "c_ns" not in data:
        data["c_ns"] = "goldilocks_" + str(data["bits"])
        data["C_NS"] = data["c_ns"].upper()


