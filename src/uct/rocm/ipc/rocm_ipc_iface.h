/*
 * Copyright 2016 - 2017 Advanced Micro Devices, Inc.
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


#ifndef ROCM_IPC_IFACE_H
#define ROCM_IPC_IFACE_H

#include <uct/base/uct_iface.h>

#include "rocm_ipc_md.h"

/** Define name of transport used for memory operation */
#define UCT_ROCM_IPC_TL_NAME    "rocmipc"


typedef struct uct_rocm_ipc_iface {
    uct_base_iface_t        super;
    uct_rocm_ipc_md_t      *rocm_md;
} uct_rocm_ipc_iface_t;


typedef struct uct_rocm_ipc_iface_config {
    uct_iface_config_t      super;
} uct_rocm_ipc_iface_config_t;

extern uct_tl_component_t uct_rocm_ipc_tl;

static UCS_F_ALWAYS_INLINE
size_t uct_rocm_ipc_iface_get_max_iov()
{
    return 1;
}

#endif
