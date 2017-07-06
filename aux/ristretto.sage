
class InvalidEncodingException(Exception): pass
class NotOnCurveException(Exception): pass

def lobit(x): return int(x) & 1
def hibit(x): return lobit(2*x)
def enc_le(x,n): return bytearray([int(x)>>(8*i) & 0xFF for i in xrange(n)])
def dec_le(x): return sum(b<<(8*i) for i,b in enumerate(x))

def isqrt(x,exn=InvalidEncodingException("Not on curve")):
    """Return 1/sqrt(x)"""
    if x==0: return 0
    if not is_square(x): raise exn
    return 1/sqrt(x)

class EdwardsPoint(object):
    """Abstract class for point an an Edwards curve; needs F,a,d to work"""
    def __init__(self,x=0,y=1):
        x = self.x = self.F(x)
        y = self.y = self.F(y)
        if y^2 + self.a*x^2 != 1 + self.d*x^2*y^2:
            raise NotOnCurveException()

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

class RistrettoPoint(EdwardsPoint):
    """Like current decaf but tweaked for simplicity"""
    
    def __eq__(self,other):
        x,y = self
        X,Y = other
        return x*Y == X*y or x*X == y*Y
    
    @staticmethod
    def sqrt(x,negative=lobit,exn=InvalidEncodingException("Not on curve")):
        if not is_square(x): raise exn
        s = sqrt(x)
        if negative(s): s=-s
        return s
        
    def encodeSpec(self):
        """Unoptimized specification for encoding"""
        x,y = self
        if self.cofactor==8 and (lobit(x*y) or x==0):
            (x,y) = (self.i*y,self.i*x)
        elif self.cofactor==4 and y==-1:
            y = 1 # Doesn't affect impl
            
        if lobit(x): y=-y
        s = self.sqrt((1-y)/(1+y),exn=Exception("Unimplemented: point is even"))
        
        return enc_le(s,self.encLen)
        
    @classmethod
    def decodeSpec(cls,s):
        """Unoptimized specification for decoding"""
        if len(s) != cls.encLen:
            raise InvalidEncodingException("wrong length %d" % len(s))
        s = dec_le(s)
        if s < 0 or s >= cls.F.modulus() or lobit(s):
            raise InvalidEncodingException("%d out of range!" % s)
        s = cls.F(s)
        
        x = cls.sqrt(-4*s^2 / (cls.d*(s^2-1)^2 + (s^2+1)^2))
        y = (1-s^2) / (1+s^2)
    
        if cls.cofactor==8 and (lobit(x*y) or x==0):
            raise InvalidEncodingException("x*y has high bit")
                
        return cls(x,y)
        
    def encode(self):
        x,y,z,t = self.xyzt()

        u1    = (z+y)*(z-y)
        u2    = x*y # = t*z
        isr   = isqrt(u1 * u2^2)
        i1    = isr*u1
        i2    = isr*u2
        z_inv = i1*i2*t

        rotate = self.cofactor==8 and lobit(t*z_inv)
        if rotate:
            magic = isqrt(-self.d-1)
            x,y = y*self.i,x*self.i
            den_inv = magic * i1
        else:
            den_inv = i2

        if lobit(x*z_inv): y = -y
        s = (z-y) * den_inv
        if self.cofactor==8 and s==0: s += 1
        if lobit(s): s=-s
        
        ret = enc_le(s,self.encLen)
        assert ret == self.encodeSpec()
        return ret
        
    @classmethod
    def decode(cls,s):
        right_answer = cls.decodeSpec(s)
        
        # Sanity check s
        if len(s) != cls.encLen:
            raise InvalidEncodingException("wrong length %d" % len(s))
        s = dec_le(s)
        if s < 0 or s >= cls.F.modulus() or lobit(s):
            raise InvalidEncodingException("%d out of range!" % s)
        s = cls.F(s)
        
        yden     = 1+s^2
        ynum     = 1-s^2
        yden_sqr = yden^2
        xden_sqr = -cls.d*ynum^2 - yden_sqr
        
        isr = isqrt(xden_sqr * yden_sqr)
        
        xden_inv = isr * yden
        yden_inv = xden_inv * isr * xden_sqr
        
        x = 2*s*xden_inv
        if lobit(x): x = -x
        y = ynum * yden_inv
    
        if cls.cofactor==8 and (lobit(x*y) or x==0):
            raise InvalidEncodingException("x*y has high bit")
            
        ret = cls(x,y)
        assert ret == right_answer
        return ret
        
    def torque(self):
        if self.cofactor == 8:
            return self.__class__(self.y*self.i, self.x*self.i)
        else:
            return self.__class__(-self.x, -self.y)
            

class Ed25519Point(RistrettoPoint):
    F = GF(2^255-19)
    d = F(-121665/121666)
    a = F(-1)
    i = sqrt(F(-1))
    cofactor = 8
    encLen = 32
    
    @classmethod
    def base(cls):
        y = cls.F(4/5)
        x = sqrt((y^2-1)/(cls.d*y^2+1))
        if lobit(x): x = -x
        return cls(x,y)

class Ed448Point(RistrettoPoint):
    F = GF(2^448-2^224-1)
    d = F(-39082)
    a = F(-1)
    cofactor = 4
    encLen = 56
    
    @classmethod
    def base(cls):
        y = cls.F(6) # FIXME: no it isn't
        x = sqrt((y^2-1)/(cls.d*y^2+1))
        if lobit(x): x = -x
        return cls(x,y)

class TestFailedException(Exception): pass
def test(cls,n):
    # TODO: test corner cases like 0,1,i
    P = cls.base()
    Q = cls()
    for i in xrange(n):
        QQ = cls.decode(Q.encode())
        if QQ != Q: raise TestFailedException("Round trip %s != %s" % (str(QQ),str(Q)))
        if Q.encode() != Q.torque().encode():
            raise TestFailedException("Can't torque %s" % str(Q))
            
        Q0 = Q + P
        if Q0 == Q: raise TestFailedException("Addition doesn't work")
        if Q0-P != Q: raise TestFailedException("Subtraction doesn't work")
        
        r = randint(1,1000)
        Q1 = Q0*r
        Q2 = Q0*(r+1)
        if Q1 + Q0 != Q2: raise TestFailedException("Scalarmul doesn't work")
        Q = Q1
    
    