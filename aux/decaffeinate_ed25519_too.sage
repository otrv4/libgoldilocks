F = GF(2^255-19)
dM = F(-121665)
d = F(-121665/121666)
ii = sqrt(F(-1))
def lobit(x): return int(x) & 1
def hibit(x): return lobit(2*x)

magic = sqrt(F(-121666))
if lobit(magic): magic = -magic

def eddsa_to_decaf(x,y):
    """
    Converts an EdDSA point to a Decaf representation, in a manner compatible
    with libdecaf.
    
    The input point must be even.
    
    Note well!  Decaf does not represent the cofactor information of a point.
    So e2d(d2e(s)) = s, but d2e(e2d(x,y)) might not be (x,y).
    """
    if x*y == 0: return 0 # This will happen anyway with straightforward square root trick
    if not is_square((1-y)/(1+y)): raise Exception("Unimplemented: odd point in eddsa_to_decaf")
    if hibit(magic/(x*y)): (x,y) = (ii*y,ii*x)
    if hibit(2*magic/x): y = -y
    s = sqrt((1-y)/(1+y))
    if hibit(s): s = -s
    return s

def isqrt_trick(to_isr,to_inv):
    to_sqrt = to_isr*to_inv^2
    if to_sqrt == 0: return 0,0 # This happens automatically in C; just to avoid problems in SAGE
    if not is_square(to_sqrt): raise Exception("Not square in isqrt_trick!")
    tmp = 1/sqrt(to_sqrt)
    isr = tmp * to_inv
    inv = tmp * isr * to_isr
    assert isr^2 == 1/to_isr
    assert inv == 1/to_inv
    return isr, inv
    

def eddsa_to_decaf_opt(x,y,z=None):
    """
    Optimized version of eddsa_to_decaf.
    
    Uses only one isqrt.
    """
    if z is None:
        # Pretend that we're in projective
        z = F.random_element()
        x *= z
        y *= z
    
    isr,inv = isqrt_trick(z^2-y^2,x*y)
    inv *= magic
    
    rotate = hibit(inv*z^2)
    if rotate:
        isr *= (z^2-y^2)*inv
        y = ii*x
    
    if hibit(2*inv*y*z) != rotate: y = -y
    s = (z-y) * isr
    
    if hibit(s): s = -s
    return s

print [eddsa_to_decaf_opt(x,y) == eddsa_to_decaf(x,y) for _,_,_,_,y1,y2 in points for x,y in [decode(y1,y2)]]

def decaf_to_eddsa(s):
    """
    Convert a Decaf representation to an EdDSA point, in a manner compatible
    with libdecaf.
    
    Note well! The Decaf representation of a point is canonical, but the EdDSA one
    is not, in that  
    """
    if s == 0: return (0,1)
    if hibit(s): raise Exception("invalid: s has high bit")
    if not is_square(s^4 + (2-4*dM)*s^2 + 1): raise Exception("invalid: not on curve")
    
    t = sqrt(s^4 + (2-4*dM)*s^2 + 1)/s
    if hibit(t): t = -t
    y = (1-s^2)/(1+s^2)
    x = 2*magic/t
    if y == 0 or lobit(t/y): raise Exception("invalid: t/y has high bit")
    assert y^2 - x^2 == 1+d*x^2*y^2
    return (x,y)
