/*
 * Copyright 2016-2017 Advanced Micro Devices, Inc.
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

#ifndef ROCM_IPC_MD_H
#define ROCM_IPC_MD_H

#include <ucs/config/types.h>
#include <ucs/debug/memtrack.h>
#include <ucs/type/status.h>
#include <uct/base/uct_md.h>



#include <hsa.h>
#include <hsa_ext_amd.h>

/** Define name of memory domain for GPU memory. Must not be larget than
    UCT_MD_COMPONENT_NAME_MAX. */
#define UCT_ROCM_IPC_MD_NAME   "rocmipc"

extern uct_md_component_t uct_rocm_ipc_md_component;

/**
 * @brief ROCm MD descriptor
 */
typedef struct uct_rocm_ipc_md {
    struct uct_md super;  /**< Domain info */

    /* rocm specific data should be here if any. */
} uct_rocm_ipc_md_t;

/**
 * ROCm  IPC memory domain configuration.
 */
typedef struct uct_rocm_ipc_md_config {
    uct_md_config_t super;
} uct_rocm_ipc_md_config_t;



/**
 * @brief ROCm packed and remote key
 */
typedef struct uct_rocm_ipc_key {
    hsa_amd_ipc_memory_t ipc_handle;  /**< IPC Handle */
    size_t               length;      /**< Size of memory */
    uintptr_t            address;     /**< Local address of memory */
} uct_rocm_ipc_key_t;

#endif
