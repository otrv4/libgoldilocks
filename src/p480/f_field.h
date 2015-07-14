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
#define GF_LIT_LIMB_BITS  60
#define GF_BITS           480
#define gf              p480_t
#define gf_mul            p480_mul
#define gf_sqr            p480_sqr
#define gf_add_RAW        p480_add_RAW
#define gf_sub_RAW        p480_sub_RAW
#define gf_mulw           p480_mulw
#define gf_bias           p480_bias
#define gf_isr            p480_isr
#define gf_weak_reduce    p480_weak_reduce
#define gf_strong_reduce  p480_strong_reduce
#define gf_serialize      p480_serialize
#define gf_deserialize    p480_deserialize

#endif /* __F_FIELD_H__ */
