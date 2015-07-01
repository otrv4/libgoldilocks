/**
 * @file decaf.h
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Master header for Decaf library.
 *
 * The Decaf library implements cryptographic operations on a elliptic curve
 * groups of prime order p.  It accomplishes this by using a twisted Edwards
 * curve (isogenous to Ed448-Goldilocks or Ed25519) and wiping out the cofactor.
 *
 * The formulas are all complete and have no special cases.  However, some
 * functions can fail.  For example, decoding functions can fail because not
 * every string is the encoding of a valid group element.
 *
 * The formulas contain no data-dependent branches, timing or memory accesses,
 * except for decaf_XXX_base_double_scalarmul_non_secret.
 */
#ifndef __DECAF_H__
#define __DECAF_H__ 1

#include <stdint.h>
#include <sys/types.h>

#include "decaf_255.h"
#include "decaf_448.h"

#endif /* __DECAF_H__ */

