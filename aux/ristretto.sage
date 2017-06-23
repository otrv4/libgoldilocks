
class InvalidEncodingException(Exception): pass
class NotOnCurveException(Exception): pass

def lobit(x): return int(x) & 1
def hibit(x): return lobit(2*x)
def enc_le(x,n): return bytearray([int(x)>>(8*i) & 0xFF for i in xrange(n)])
def dec_le(x): return sum(b<<(8*i) for i,b in enumerate(x))

class EdwardsPoint(object):
    """Abstract class for point an an Edwards curve; needs F,a,d to work"""
    def __init__(self,x=0,y=1):
        x = self.x = self.F(x)
        y = self.y = self.F(y)
        if y^2 + self.a*x^2 != 1 + self.d*x^2*y^2:
            raise NotOnCurveException()

    def __repr__(self):
        return "%s(%d,%d)" % (self.__class__.__name__, self.x, self.y)

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

class Ed25519Point(EdwardsPoint):
    F = GF(2^255-19)
    d = F(-121665/121666)
    a = F(-1)
    i = sqrt(Ed25519Point.F(-1))
    
    @classmethod
    def base(cls):
        y = cls.F(4/5)
        x = sqrt((y^2-1)/(cls.d*y^2+1))
        if lobit(x): x = -x
        return cls(x,y)
        
    def torque(self):
        return self.__class__(self.y*self.i, self.x*self.i)

class RistrettoPoint(Ed25519Point):
    """Like current decaf but tweaked for simplicity"""
    encLen = 32
    
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
        
    def encode(self):
        x,y = self
        if lobit(x*y) or x==0: (x,y) = (self.i*y,self.i*x)
        if lobit(x): x,y = -x,-y
        s = self.sqrt((1-y)/(1+y),exn=Exception("Unimplemented: point is even"))
        return enc_le(s,self.encLen)
        
    @classmethod
    def decode(cls,s):
        if len(s) != cls.encLen:
            raise InvalidEncodingException("wrong length %d" % len(s))
        s = dec_le(s)
        if s < 0 or s >= cls.F.modulus() or lobit(s):
            raise InvalidEncodingException("%d out of range!" % s)
        s = cls.F(s)
        
        x = cls.sqrt(-4*s^2 / (cls.d*(s^2-1)^2 + (s^2+1)^2))
        y = (1-s^2) / (1+s^2)
    
        if lobit(x*y) or x==0:
            raise InvalidEncodingException("x*y has high bit")
            
        return cls(x,y)

class DecafPoint(Ed25519Point):
    """Works like current decaf"""
    dMont = Ed25519Point.F(-121665)
    magic = sqrt(dMont-1)
    encLen = 32
    
    def __eq__(self,other):
        x,y = self
        X,Y = other
        return x*Y == X*y or x*X == y*Y
    
    def encode(self):
        x,y = self
        a,d = self.a,self.d
        
        if x*y == 0:
            # This will happen anyway with straightforward square root trick
            return enc_le(0,self.encLen)

        if not is_square((1-y)/(1+y)):
            raise Exception("Unimplemented: odd point in RistrettoPoint.encode")
        
        # Choose representative in 4-torsion group
        if hibit(self.magic/(x*y)): (x,y) = (self.i*y,self.i*x)
        if hibit(2*self.magic/x): x,y = -x,-y
        
        s = sqrt((1-y)/(1+y))
        if hibit(s): s = -s
        return enc_le(s,self.encLen)
        
    @classmethod
    def decode(cls,s):
        if len(s) != cls.encLen:
            raise InvalidEncodingException("wrong length %d" % len(s))
        s = dec_le(s)
        if s == 0: return cls(0,1)
        if s < 0 or s >= (cls.F.modulus()+1)/2:
            raise InvalidEncodingException("%d out of range!" % s)
        s = cls.F(s)
        
        if not is_square(s^4 + (2-4*cls.dMont)*s^2 + 1):
            raise InvalidEncodingException("Not on curve")
    
        t = sqrt(s^4 + (2-4*cls.dMont)*s^2 + 1)/s
        if hibit(t): t = -t
        
        y = (1-s^2)/(1+s^2)
        x = 2*cls.magic/t
    
        if y == 0 or lobit(t/y):
            raise InvalidEncodingException("t/y has high bit")
            
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
    
    