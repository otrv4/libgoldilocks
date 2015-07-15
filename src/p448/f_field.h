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
#define GF_LIT_LIMB_BITS  56
#define GF_BITS           448
#define gf                gf_448_t
#define gf_s              gf_448_s
#define gf_mul            p448_mul
#define gf_sqr            p448_sqr
#define gf_add_RAW        p448_add_RAW
#define gf_sub_RAW        p448_sub_RAW
#define gf_mulw           p448_mulw
#define gf_bias           p448_bias
#define gf_isr            p448_isr
#define gf_weak_reduce    p448_weak_reduce
#define gf_strong_reduce  p448_strong_reduce
#define gf_serialize      p448_serialize
#define gf_deserialize    p448_deserialize

#endif /* __F_FIELD_H__ */
