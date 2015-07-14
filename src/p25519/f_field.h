/**
 * @file f_field.h
 * @brief Field-specific code.
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 */
#ifndef __F_FIELD_H__
#define __F_FIELD_H__ 1

#include "constant_time.h"
#include <string.h>

#include "f_impl.h"
#define GF_LIT_LIMB_BITS  51
#define GF_BITS           255
#define gf              gf_25519_t
#define gf_s              gf_25519_s
#define gf_mul            gf_25519_mul
#define gf_sqr            gf_25519_sqr
#define gf_add_RAW        gf_25519_add_RAW
#define gf_sub_RAW        gf_25519_sub_RAW
#define gf_mulw           gf_25519_mulw
#define gf_bias           gf_25519_bias
#define gf_isr            gf_25519_isr
#define gf_weak_reduce    gf_25519_weak_reduce
#define gf_strong_reduce  gf_25519_strong_reduce
#define gf_serialize      gf_25519_serialize
#define gf_deserialize    gf_25519_deserialize
#define SQRT_MINUS_ONE    P25519_SQRT_MINUS_ONE

#endif /* __F_FIELD_H__ */
