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

#include <string.h>
#include "constant_time.h"

#include "f_impl.h"
#define GF_LIT_LIMB_BITS  58
#define GF_BITS           521
#define gf              p521_t
#define gf_mul            p521_mul
#define gf_sqr            p521_sqr
#define gf_add_RAW        p521_add_RAW
#define gf_sub_RAW        p521_sub_RAW
#define gf_mulw           p521_mulw
#define gf_bias           p521_bias
#define gf_isr            p521_isr
#define gf_weak_reduce    p521_weak_reduce
#define gf_strong_reduce  p521_strong_reduce
#define gf_serialize      p521_serialize
#define gf_deserialize    p521_deserialize

#endif /* __F_FIELD_H__ */
