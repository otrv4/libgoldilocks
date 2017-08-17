import binascii
class InvalidEncodingException(Exception): pass
class NotOnCurveException(Exception): pass
class SpecException(Exception): pass

def lobit(x): return int(x) & 1
def hibit(x): return lobit(2*x)
def enc_le(x,n): return bytearray([int(x)>>(8*i) & 0xFF for i in xrange(n)])
def dec_le(x): return sum(b<<(8*i) for i,b in enumerate(x))
def randombytes(n): return bytearray([randint(0,255) for _ in range(n)])

def optimized_version_of(spec):
    def decorator(f):
        def wrapper(self,*args,**kwargs):
            try: spec_ans = getattr(self,spec,spec)(*args,**kwargs),None
            except Exception as e: spec_ans = None,e
            try: opt_ans = f(self,*args,**kwargs),None
            except Exception as e: opt_ans = None,e
            if spec_ans[1] is None and opt_ans[1] is not None:
                raise SpecException("Mismatch in %s: spec returned %s but opt threw %s"
                    % (f.__name__,str(spec_ans[0]),str(opt_ans[1])))
            if spec_ans[1] is not None and opt_ans[1] is None:
                raise SpecException("Mismatch in %s: spec threw %s but opt returned %s"
                    % (f.__name__,str(spec_ans[1]),str(opt_ans[0])))
            if spec_ans[0] != opt_ans[0]:
                raise SpecException("Mismatch in %s: %s != %s"
                    % (f.__name__,str(spec_ans[0]),str(opt_ans[0])))
            if opt_ans[1] is not None: raise opt_ans[1]
            else: return opt_ans[0]
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator
    
def xsqrt(x,exn=InvalidEncodingException("Not on curve")):
    """Return sqrt(x)"""
    if not is_square(x): raise exn
    s = sqrt(x)
    if lobit(s): s=-s
    return s        

def isqrt(x,exn=InvalidEncodingException("Not on curve")):
    """Return 1/sqrt(x)"""
    if x==0: return 0
    if not is_square(x): raise exn
    return 1/sqrt(x)

def isqrt_i(x):
    """Return 1/sqrt(x) or 1/sqrt(zeta * x)"""
    if x==0: return 0
    gen = x.parent(-1)
    while is_square(gen): gen = sqrt(gen)
    if is_square(x): return True,1/sqrt(x)
    else: return False,1/sqrt(x*gen)

class EdwardsPoint(object):
    """Abstract class for point an an Edwards curve; needs F,a,d to work"""
    def __init__(self,x=0,y=1):
        x = self.x = self.F(x)
        y = self.y = self.F(y)
        if y^2 + self.a*x^2 != 1 + self.d*x^2*y^2:
            raise NotOnCurveException(str(self))

    def __repr__(self):
        return "%s(0x%x,0x%x)" % (self.__class__.__name__, self.x, self.y)

    def __iter__(self):
        yield self.x
        yield self.y

    def __add__(self,other):
        x,y = self
        X,Y = other
        a,d = self.a,self.d
        return self.__class__(
            (x*Y+y*X)/(1+d*x*y*X*Y), 
            (y*Y-a*x*X)/(1-d*x*y*X*Y)
        )
    
    def __neg__(self): return self.__class__(-self.x,self.y)
    def __sub__(self,other): return self + (-other)
    def __rmul__(self,other): return self*other
    def __eq__(self,other): return tuple(self) == tuple(other)
    def __ne__(self,other): return not (self==other)
    
    def __mul__(self,exp):
        exp = int(exp)
        total = self.__class__()
        work  = self
        while exp != 0:
            if exp & 1: total += work
            work += work
            exp >>= 1
        return total
    
    def xyzt(self):
        x,y = self
        z = self.F.random_element()
        return x*z,y*z,z,x*y*z
        
    def torque(self):
        """Apply cofactor group, except keeping the point even"""
        if self.cofactor == 8:
            return self.__class__(self.y*self.i, self.x*self.i)
        else:
            return self.__class__(-self.x, -self.y)

class RistrettoPoint(EdwardsPoint):
    """Like current decaf but tweaked for simplicity"""
    def __eq__(self,other):
        x,y = self
        X,Y = other
        return x*Y == X*y or x*X == y*Y
    
    @classmethod
    def bytesToGf(cls,bytes,mustBeProper=True,mustBePositive=False):
        """Convert little-endian bytes to field element, sanity check length"""
        if len(bytes) != cls.encLen:
            raise InvalidEncodingException("wrong length %d" % len(bytes))
        s = dec_le(bytes)
        if mustBeProper and s >= cls.F.modulus():
            raise InvalidEncodingException("%d out of range!" % s)
        if mustBePositive and lobit(s):
            raise InvalidEncodingException("%d is negative!" % s)
        return cls.F(s)
        
    def encodeSpec(self):
        """Unoptimized specification for encoding"""
        x,y = self
        if self.cofactor==8 and (lobit(x*y) or y==0):
            (x,y) = (self.i*y,self.i*x)
            
        if y == -1: y = 1 # Avoid divide by 0; doesn't affect impl
            
        if lobit(x): x,y = -x,-y
        s = xsqrt(self.a*(y-1)/(y+1),exn=Exception("Unimplemented: point is odd: " + str(self)))
        
        return enc_le(s,self.encLen)
        
    @classmethod
    def decodeSpec(cls,s):
        """Unoptimized specification for decoding"""
        s = cls.bytesToGf(s,mustBePositive=True)
        
        a,d = cls.a,cls.d
        x = xsqrt(4*s^2 / (a*d*(1+a*s^2)^2 - (1-a*s^2)^2))
        y = (1+a*s^2) / (1-a*s^2)
    
        if cls.cofactor==8 and (lobit(x*y) or y==0):
            raise InvalidEncodingException("x*y has high bit")
                
        return cls(x,y)

    @optimized_version_of("encodeSpec")
    def encode(self):
        """Encode, optimized version"""
        a,d = self.a,self.d
        x,y,z,t = self.xyzt()
        
        u1    = a*(y+z)*(y-z)
        u2    = x*y # = t*z
        isr   = isqrt(u1*u2^2)
        i1    = isr*u1
        i2    = isr*u2
        z_inv = i1*i2*t

        rotate = self.cofactor==8 and lobit(t*z_inv)
        if rotate:
            x,y = y*self.i,x*self.i
            den_inv = self.magic * i1
        else:
            den_inv = i2

        if lobit(x*z_inv): y = -y
        s = (z-y) * den_inv
        if lobit(s): s=-s
        
        return enc_le(s,self.encLen)
        
    @classmethod
    @optimized_version_of("decodeSpec")
    def decode(cls,s):
        """Decode, optimized version"""
        s = cls.bytesToGf(s,mustBePositive=True)
        
        a,d = cls.a,cls.d
        yden     = 1-a*s^2
        ynum     = 1+a*s^2
        yden_sqr = yden^2
        xden_sqr = a*d*ynum^2 - yden_sqr
        
        isr = isqrt(xden_sqr * yden_sqr)
        
        xden_inv = isr * yden
        yden_inv = xden_inv * isr * xden_sqr
        
        x = 2*s*xden_inv
        if lobit(x): x = -x
        y = ynum * yden_inv
    
        if cls.cofactor==8 and (lobit(x*y) or y==0):
            raise InvalidEncodingException("x*y is invalid: %d, %d" % (x,y))
            
        return cls(x,y)
       
    @classmethod     
    def fromJacobiQuartic(cls,s,t,sgn=1):
        """Convert point from its Jacobi Quartic representation"""
        a,d = cls.a,cls.d
        assert s^4 - 2*cls.a*(1-2*d/(d-a))*s^2 + 1 == t^2
        x = 2*s*cls.magic / t
        if lobit(x): x = -x # TODO: doesn't work without resolving x
        y = (1+a*s^2) / (1-a*s^2)
        return cls(sgn*x,y)
            
    @classmethod
    def elligatorSpec(cls,r0):
        a,d = cls.a,cls.d
        r = cls.qnr * cls.bytesToGf(r0)^2
        den = (d*r-a)*(a*r-d)
        n1 = cls.a*(r+1)*(a+d)*(d-a)/den
        n2 = r*n1
        if is_square(n1):
            sgn,s,t = 1,xsqrt(n1), -(r-1)*(a+d)^2 / den - 1
        else:
            sgn,s,t = -1,xsqrt(n2), r*(r-1)*(a+d)^2 / den - 1
        
        ret = cls.fromJacobiQuartic(s,t,sgn)
        return ret
            
    @classmethod
    @optimized_version_of("elligatorSpec")
    def elligator(cls,r0):
        a,d = cls.a,cls.d
        r0 = cls.bytesToGf(r0)
        r = cls.qnr * r0^2
        den = (d*r-a)*(a*r-d)
        num = cls.a*(r+1)*(a+d)*(d-a)
        
        iss,isri = isqrt_i(num*den)
        if iss: sgn,twiddle =  1,1
        else:   sgn,twiddle = -1,r0*cls.qnr
        isri *= twiddle
        s = isri*num
        t = isri*s*(r-1)*(d+a)^2 + sgn
        return cls.fromJacobiQuartic(s,t,sgn)
       
class Ed25519Point(RistrettoPoint):
    F = GF(2^255-19)
    d = F(-121665/121666)
    a = F(-1)
    i = sqrt(F(-1))
    qnr = i
    magic = isqrt(a*d-1)
    cofactor = 8
    encLen = 32
    
    @classmethod
    def base(cls):
        y = cls.F(4/5)
        x = sqrt((y^2-1)/(cls.d*y^2+1))
        if lobit(x): x = -x
        return cls(x,y)

class TwistedEd448GoldilocksPoint(RistrettoPoint):
    F = GF(2^448-2^224-1)
    d = F(-39082)
    a = F(-1)
    qnr = -1
    magic = isqrt(a*d-1)
    cofactor = 4
    encLen = 56

    @classmethod
    def base(cls):
        y = cls.F(6) # TODO: no it isn't
        x = sqrt((y^2-1)/(cls.d*y^2+1))
        if lobit(x): x = -x
        return cls(x,y)

class Ed448GoldilocksPoint(RistrettoPoint):
    # TODO: decaf vs ristretto
    F = GF(2^448-2^224-1)
    d = F(-39081)
    a = F(1)
    qnr = -1
    magic = isqrt(a*d-1)
    cofactor = 4
    encLen = 56
    
    @classmethod
    def base(cls):
        return cls(
        0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555,
        0xae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed
        )

class IsoEd448Point(RistrettoPoint):
    F = GF(2^448-2^224-1)
    d = F(1/39081+1)
    a = F(1)
    qnr = -1
    magic = isqrt(a*d-1)
    cofactor = 4
    encLen = 56
    
    @classmethod
    def base(cls):
        # = ..., -3/2
        return cls.decodeSpec(bytearray(binascii.unhexlify(
            "00000000000000000000000000000000000000000000000000000000"+
            "fdffffffffffffffffffffffffffffffffffffffffffffffffffffff")))

class TestFailedException(Exception): pass

def test(cls,n):
    # TODO: test corner cases like 0,1,i
    P = cls.base()
    Q = cls()
    for i in xrange(n):
        #print binascii.hexlify(Q.encode())
        QQ = cls.decode(Q.encode())
        if QQ != Q: raise TestFailedException("Round trip %s != %s" % (str(QQ),str(Q)))
        
        QT = Q
        QE = Q.encode()
        for h in xrange(cls.cofactor):
            QT = QT.torque()
            if QT.encode() != QE:
                raise TestFailedException("Can't torque %s,%d" % (str(Q),h+1))
            
        Q0 = Q + P
        if Q0 == Q: raise TestFailedException("Addition doesn't work")
        if Q0-P != Q: raise TestFailedException("Subtraction doesn't work")
        
        r = randint(1,1000)
        Q1 = Q0*r
        Q2 = Q0*(r+1)
        if Q1 + Q0 != Q2: raise TestFailedException("Scalarmul doesn't work")
        Q = Q1
test(Ed25519Point,100)
test(TwistedEd448GoldilocksPoint,100)
test(Ed448GoldilocksPoint,100)
test(IsoEd448Point,100)
    

def testElligator(cls,n):
    for i in xrange(n):
        cls.elligator(randombytes(cls.encLen))
testElligator(Ed25519Point,100)
testElligator(Ed448GoldilocksPoint,100)
testElligator(TwistedEd448GoldilocksPoint,100)
testElligator(IsoEd448Point,100)
