from ctypes import *
from base64 import *

GOLDILOCKS = CDLL("build/lib/libgoldilocks.so")

F = GF(2^448-2^224-1)
d = -39081
E = EllipticCurve(F,[0,2-4*d,0,1,0])
p_tor4 = E.lift_x(-1)
Tor = [p_tor4 * i for i in xrange(4)]
q = 2^446-0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
FQ = GF(q)
isoMagic = 1/sqrt(F(39082/39081)-1)

passing = True

# TODO: pathological cases
# TODO: Elligator
# TODO: double scalar mul

def random_array(length):
    answer = "".join([chr(randint(0,255)) for i in xrange(length)])
    return answer

def from_le(buf):
    return sum([256^i * ord(x) for i,x in enumerate(buf)])

def youfail(why,n):
    print ("Fail on test %d!"%n), why
    global passing
    passing = False

def run_test(i):
    try:
        s = GoldilocksScalar.random()
        t = GoldilocksScalar.random()
        p = GoldilocksPoint.random()
        q = GoldilocksPoint.random()
        s*p + t*q
        if s*(t*p) != (s*t)*p:
            raise Exception("Mul doesn't work")
        (p+q-p-q).ser() # i guess...
    except Exception, e:
        youfail(e,i)

def run_all_tests(n = 100):
    for testno in xrange(n):
        run_test(testno)
    if passing:
        print "Passed all %d tests." % n

def to_le(x,n):
    x = int(x)
    if x >= 256^n:
        raise Exception("Integer too big in to_le(%d,%d)" % (x,n))
    return "".join([chr(x>>(8*i) & 255) for i in xrange(n)])

class GoldilocksScalar():
    _UNDER = c_uint64 * int(7)
    def __init__(self,cstruct=None,scalar=None):
        if cstruct is None:
            cstruct = GoldilocksScalar._UNDER()
            memmove(addressof(cstruct),
                GOLDILOCKS.goldilocks_448_scalar_zero,
                8*7
            )
        if scalar is None:
            scalar = E(0)
        self.cstruct = cstruct
        self.scalar = scalar

        self._check()

    @staticmethod
    def _c_deser(str):
        buffer = (c_uint8*int(56)).from_buffer_copy(str)
        cstruct = GoldilocksScalar._UNDER()
        ret = GOLDILOCKS.goldilocks_448_scalar_decode(cstruct,buffer,c_uint64(-1))
        if ret != -1:
            raise Exception("scalar didn't decode")
        return cstruct

    @staticmethod
    def _sage_deser(str):
        s = from_le(str)
        if s >= FQ.cardinality(): raise Exception("scalar didn't decode")
        return FQ(s)

    def __eq__(self,other):
        csays = bool(GOLDILOCKS.goldilocks_448_scalar_eq(self.cstruct,other.cstruct))
        sagesays = any([self.scalar == other.scalar + t for t in Tor])
        if csays != sagesays:
            raise Exception("C and SAGE don't agree: %d %d" % (csays, sagesays))
        return csays

    def __ne__(self,other):
        return not self==other

    def __add__(self,other):
        cstruct = GoldilocksScalar._UNDER()
        GOLDILOCKS.goldilocks_448_scalar_add(cstruct,self.cstruct,other.cstruct)
        return GoldilocksScalar(cstruct,self.scalar + other.scalar)

    def __sub__(self,other):
        cstruct = GoldilocksScalar._UNDER()
        GOLDILOCKS.goldilocks_448_scalar_sub(cstruct,self.cstruct,other.cstruct)
        return GoldilocksScalar(cstruct,self.scalar - other.scalar)

    def __mul__(self,other):
        if isinstance(other,GoldilocksScalar):
            cstruct = GoldilocksScalar._UNDER()
            GOLDILOCKS.goldilocks_448_scalar_mul(cstruct,self.cstruct,other.cstruct)
            return GoldilocksScalar(cstruct,self.scalar * other.scalar)
        elif isinstance(other,GoldilocksPoint):
            cstruct = GoldilocksPoint._UNDER()
            GOLDILOCKS.goldilocks_448_point_scalarmul(cstruct,other.cstruct,self.cstruct)
            return GoldilocksPoint(cstruct,int(self.scalar) * other.point)
        else: raise Exception("Nope")

    def __div__(self,other):
        return self / other.inverse()

    def inverse(self):
        cstruct = GoldilocksScalar._UNDER()
        z = GOLDILOCKS.goldilocks_448_scalar_invert(cstruct,self.cstruct)
        if bool(z) != (self.scalar == 0):
            raise Exception("C and SAGE don't agree")
        return GoldilocksScalar(cstruct,1/self.scalar)

    def __neg__(self):
        cstruct = GoldilocksScalar._UNDER()
        GOLDILOCKS.goldilocks_448_scalar_negate(cstruct,self.cstruct)
        return GoldilocksScalar(cstruct,-self.scalar)

    def __str__(self):
        return " ".join(["%02x"%ord(b) for b in self.ser()])

    def __repr__(self):
        return "GoldilocksScalar.fromInt(%d)" % self.scalar

    @classmethod
    def fromInt(cls,i):
        return cls.deser(to_le(i,56))

    def to64(self):
        return b64encode(self.ser())

    @classmethod
    def from64(cls,str):
        return cls.deser(b64decode(str))

    @classmethod
    def deser(cls,str):
        good = True
        try: cstruct = cls._c_deser(str)
        except Exception: good = False

        good2 = True
        try: scalar = cls._sage_deser(str)
        except Exception: good2 = False

        if good != good2:
            raise Exception("C and SAGE don't agree")
        elif not good:
            raise Exception("scalar didn't decode")

        return cls(cstruct,scalar)

    @classmethod
    def random(cls):
        while True:
            try: return cls.deser(random_array(56))
            except Exception: pass

    @staticmethod
    def _c_ser(cstruct):
        buffer = (c_uint8*int(56))()
        GOLDILOCKS.goldilocks_448_scalar_encode(buffer,cstruct)
        return str(bytearray(buffer))

    def ser(self):
        return self._c_ser(self.cstruct)

    @staticmethod
    def _sage_ser(P):
        return to_le(P,56)

    def _check(self):
        ss = self._sage_ser(self.scalar)
        cs = self._c_ser(self.cstruct)
        if ss != cs:
            print ss
            print cs
            raise Exception("Check failed!")
        return True

class GoldilocksPoint():
    @staticmethod
    def _UNDER():
        size = int(8*8*4)
        alignment = 32
        buf1 = bytearray(size+alignment-1)
        buf2 = (c_char * int(size+alignment-1)).from_buffer(buf1)
        raw_addr = addressof(buf2)
        offset = (-raw_addr) % alignment
        return (c_char*size).from_buffer(buf2,int(offset))

    def __init__(self,cstruct=None,point=None):
        if cstruct is None:
            cstruct = GoldilocksPoint._UNDER()
            memmove(addressof(cstruct),
                GOLDILOCKS.goldilocks_448_point_identity,
                8*8*4
            )
        if point is None:
            point = E(0)
        self.cstruct = cstruct
        self.point = point

        self._check()

    @staticmethod
    def _c_deser(str):
        buffer = (c_uint8*int(56)).from_buffer_copy(str)
        cstruct = GoldilocksPoint._UNDER()
        ret = GOLDILOCKS.goldilocks_448_point_decode(cstruct,buffer,c_uint64(-1))
        if ret != -1:
            raise Exception("Point didn't decode")
        return cstruct

    @staticmethod
    def _sage_deser(str):
        s = from_le(str)
        if is_odd(s): raise Exception("Point didn't decode")
        if (s==0): return E(0)
        if not E.is_x_coord(s^2): raise Exception("Point didn't decode")
        P = E.lift_x(s^2)
        if is_odd(int(2*s^2*isoMagic/P.xy()[1])): P = -P
        return P

    def __eq__(self,other):
        csays = bool(GOLDILOCKS.goldilocks_448_point_eq(self.cstruct,other.cstruct))
        sagesays = any([self.point == other.point + t for t in Tor])
        if csays != sagesays:
            raise Exception("C and SAGE don't agree: %d %d" % (csays, sagesays))
        return csays

    def __ne__(self,other):
        return not self==other

    def __add__(self,other):
        cstruct = GoldilocksPoint._UNDER()
        GOLDILOCKS.goldilocks_448_point_add(cstruct,self.cstruct,other.cstruct)
        return GoldilocksPoint(cstruct,self.point + other.point)

    def __sub__(self,other):
        cstruct = GoldilocksPoint._UNDER()
        GOLDILOCKS.goldilocks_448_point_sub(cstruct,self.cstruct,other.cstruct)
        return GoldilocksPoint(cstruct,self.point - other.point)

    def __mul__(self,other):
        if isinstance(other,GoldilocksScalar):
            return other*self
        else:
            raise Exception("nope")

    def __div__(self,other):
        if isinstance(other,GoldilocksScalar):
            return other.inverse()*self
        else:
            raise Exception("nope")

    def __neg__(self):
        cstruct = GoldilocksPoint._UNDER()
        GOLDILOCKS.goldilocks_448_point_negate(cstruct,self.cstruct)
        return GoldilocksPoint(cstruct,-self.point)

    def __str__(self):
        return " ".join(["%02x"%ord(b) for b in self.ser()])

    def __repr__(self):
        return "GoldilocksPoint.from64('%s')" % self.to64()

    def to64(self):
        return b64encode(self.ser())

    @classmethod
    def from64(cls,str):
        return cls.deser(b64decode(str))

    @classmethod
    def deser(cls,str):
        good = True
        try: cstruct = cls._c_deser(str)
        except Exception: good = False

        good2 = True
        try: point = cls._sage_deser(str)
        except Exception: good2 = False

        if good != good2:
            raise Exception("C and SAGE don't agree")
        elif good == False:
            raise Exception("Point didn't decode")
        return cls(cstruct,point)

    @classmethod
    def random(cls):
        while True:
            try: return cls.deser(random_array(56))
            except Exception: pass

    @staticmethod
    def _c_ser(cstruct):
        buffer = (c_uint8*int(56))()
        GOLDILOCKS.goldilocks_448_point_encode(buffer,cstruct)
        return str(bytearray(buffer))

    def ser(self):
        return self._c_ser(self.cstruct)

    @staticmethod
    def _sage_ser(P):
        if P == E(0): return to_le(0,56)
        x,y = P.xy()
        s = sqrt(x)
        if s==0: return to_le(0,56)
        if is_odd(int(2*s^2*isoMagic/y)): s = 1/s
        if is_odd(int(s)): s = -s
        return to_le(s,56)

    def _check(self):
        ss = self._sage_ser(self.point)
        cs = self._c_ser(self.cstruct)
        if ss != cs:
            print "SAGE",b64encode(ss)
            print "C   ",b64encode(cs)
            raise Exception("Check failed!")
        return True

run_all_tests()

