/*
 * Copyright 2016 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef ROCM_MD_H
#define ROCM_MD_H

#include <ucs/config/types.h>
#include <ucs/debug/memtrack.h>
#include <ucs/type/status.h>
#include <uct/base/uct_md.h>

#define UCT_ROCM_MD_NAME           "rocm_gpu"

extern uct_md_component_t uct_rocm_md_component;

/**
 * @brief ROCM MD descriptor
 */
typedef struct uct_rocm_md {
    struct uct_md super;  /**< Domain info */
    // rocm specific data should be here.
} uct_rocm_md_t;

/**
 * @brief ROCM packed and remote key
 */
typedef struct uct_rocm_key {
    char  ipc[8];      /**< IPC Handle */
    uint64_t  length;  /**< Request length */
    uintptr_t address; /**< Base addr for the registration */
} uct_rocm_key_t;

#endif
