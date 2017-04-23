# Decaf elliptic curve library

This library is for elliptic curve research and practical application.
It currently supports Ed448-Goldilocks and Curve25519.

## Mailing lists

Because this is new software, please expect it to have bugs, perhaps
even critical security bugs.  If you are using it, please sign up for
updates:

* Security-critical announcements (very low volume, God willing): decaf-security@googlegroups.com
* New version announcements (low volume): decaf-announce@googlegroups.com
* Library discussion (potentially more volume): decaf-discuss@googlegroups.com

## General elliptic curve operations.

This is a multi-purpose elliptic curve library.  There is a C library,
and a set of C++ wrapper headers.  The C++ code consists entirely of
inline calls, and has no compiled component.

The library implements a fairly complete suite of operations on the
supported curves:

* Point and scalar serialization and deserialization.
* Point addition, subtraction, doubling, and equality.
* Point multiplication by scalars.  Accelerated double- and dual-scalar multiply.
* Scalar addition, subtraction, multiplication, division, and equality.
* Construction of precomputed tables from points.  Precomputed scalarmul.
* Hashing to the curve with an Elligator variant.  Inverse of elligator
   for steganography.  These are useful eg for PAKE.

Internally, the library uses twisted Edwards curves with the "decaf"
technique to remove the curve's cofactor of 4 or 8.  More about that
later.  The upshot is that systems using the "decaf" interface will
be using a prime-order group, which mitigates one of the few
disadvantages of Edwards curves.  However, this means that it is not
able to implement systems which care about cofactor information.

The goal of this library is not only to follow best practices, but to
make it easier for clients of the library to follow best practices.
With a few well-marked exceptions, the functions in this library should
be strongly constant-time: they do not allow secret data to flow to
array indices, nor to control decisions except for a final failure
check.  Furthermore, the C++ wrapping uses RAII to automatically clear
sensitive data, and has interfaces designed to prevent certain mistakes.

## CFRG cryptosystems.

The library additionally supports two cryptosystems defined by the
Crypto Forum Research Group (CFRG): the X448/X25519 Diffie-Hellman
functions, and the EdDSA signature scheme.  Future versions might
support additional operations on these curves, such as precomputed
signature verification or conversion of Ed25519 keys to Curve25519
keys.  (Or they might not.  We'll see.)

## Symmetric crypto and hashing

The Decaf library doesn't implement much symmetric crypto, but it does
contain the hash functions required by the CFRG cryptosystems: SHA512,
SHA-3 and SHAKE.

## Internals

The "decaf" technique is described in https://eprint.iacr.org/2015/673
While the title of that paper is "removing cofactors through point
compression", it might be more accurate to say "through quotients and
isogenies".  The internal representation of points is as "even" elements
of a twisted Edwards curve with a=-1.  Using this subgroup removes a
factor of 2 from the cofactor.  The remaining factor of 2 or 4 is
removed with a quotient group: any two points which differ by an element
of the 2- or 4-torsion subgroup are considered equal to each other.

When a point is written out to wire format, it is converted (by isogeny)
to a Jacobi quartic curve, which is halfway between an Edwards curve
and a Montgomery curve.  One of the 4 or 8 equivalent points on the
Jacobi quartic is chosen (it is "distinguished" according to certain
criteria, such as having a positive x-coordinate).  The x-coordinate of
this point is written out.  The y-coordinate is not written out, but the
decoder knows which of the two possible y-coordinates is correct because
of the distinguishing rules.  See the paper for more details.

## Licensing

Most of the source files here are by Mike Hamburg.  Those files are (c)
2014-2016 Cryptography Research, Inc (a division of Rambus). All of these
files are usable under the MIT license contained in LICENSE.txt.

## Caveats

As mentioned in the license, there is absolutely NO WARRANTY on any of this
code.  This is an early release, and is likely to have security-critical
bugs despite my best efforts.

I've attempted to protect against timing attacks and invalid point attacks,
but as of yet I've made no attempt to protect against power analysis.

Cheers,
-- Mike Hamburg
