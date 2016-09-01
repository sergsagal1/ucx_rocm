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

#include "rocm_md.h"

#include <ucs/debug/log.h>
#include <ucs/sys/sys.h>
#include <ucs/debug/memtrack.h>

#include <hsa.h>
#include <hsa_ext_amd.h>


static ucs_status_t uct_rocm_md_query(uct_md_h md, uct_md_attr_t *md_attr)
{
    ucs_trace("uct_rocm_md_query");

    md_attr->rkey_packed_size  = sizeof(uct_rocm_key_t);
    md_attr->cap.flags         = UCT_MD_FLAG_REG;
    md_attr->cap.max_alloc     = 0;
    md_attr->cap.max_reg       = ULONG_MAX;
    md_attr->reg_cost.overhead = 0;
    md_attr->reg_cost.growth   = 0;

    memset(&md_attr->local_cpus, 0xff, sizeof(md_attr->local_cpus));
    return UCS_OK;
}

static ucs_status_t uct_rocm_query_md_resources(uct_md_resource_desc_t **resources_p,
                                                unsigned *num_resources_p)
{
    ucs_trace("uct_rocm_query_md_resources");

    ucs_status_t status;

    status = uct_single_md_resource(&uct_rocm_md_component, resources_p,
                                  num_resources_p);

    ucs_trace("rocm md name: %s, resources %d", (*resources_p)->md_name, *num_resources_p);

    return status;
}

static void uct_rocm_md_close(uct_md_h md)
{
    uct_rocm_md_t *rocm_md = (uct_rocm_md_t *)md;
    hsa_status_t status = hsa_shut_down();

    if (HSA_STATUS_SUCCESS == status) {
      ucs_error("Failed to shutdown HSA RT. HSA Status : %d", status);
    }

    ucs_free(rocm_md);
}

static ucs_status_t uct_rocm_mem_reg(uct_md_h md, void *address, size_t length,
                                     uct_mem_h *memh_p)
{
//    uct_rocm_md_t *rocm_md = (uct_rocm_md_t *)md;
    uct_rocm_key_t *key;

    key = ucs_malloc(sizeof(uct_rocm_key_t), "uct_rocm_key_t");
    if (NULL == key) {
        ucs_error("Failed to allocate memory for uct_rocm_key_t");
        return UCS_ERR_NO_MEMORY;
    }

    // TODO: Call HSA RT IPC to get import  IPC handle
    // key->ipc_handle  = hsa_export_handle(address);

    key->address = (uintptr_t)address;
    key->length  = (uint64_t) length;

    *memh_p = key;
    return UCS_OK;
}

static ucs_status_t uct_rocm_mem_dereg(uct_md_h md, uct_mem_h memh)
{
    uct_rocm_key_t *key = (uct_rocm_key_t *)memh;

    // TODO: Call HSA RT IPC to destroy exported IPC handle

    ucs_free(key);
    return UCS_OK;
}

static ucs_status_t uct_rocm_rkey_pack(uct_md_h md, uct_mem_h memh,
                                       void *rkey_buffer)
{
    uct_rocm_key_t *packed = (uct_rocm_key_t*)rkey_buffer;
    uct_rocm_key_t *key = (uct_rocm_key_t *)memh;
    packed->length  = (uint64_t)key->length;
    packed->address = (uintptr_t)key->address;
    // packed->ipc_handle = key->ipc_handle;

    ucs_trace("packed rkey: length  0x%"PRIx64" address %"PRIxPTR,
              key->length, key->address);
    return UCS_OK;
}
static ucs_status_t uct_rocm_rkey_unpack(uct_md_component_t *mdc,
                                         const void *rkey_buffer, uct_rkey_t *rkey_p,
                                         void **handle_p)
{
    uct_rocm_key_t *packed = (uct_rocm_key_t *)rkey_buffer;
    uct_rocm_key_t *key;

    key = ucs_malloc(sizeof(uct_rocm_key_t), "uct_rocm_key_t");
    if (NULL == key) {
        ucs_error("Failed to allocate memory for uct_rocm_key_t");
        return UCS_ERR_NO_MEMORY;
    }
    key->length  = packed->length;
    key->address = packed->address;
    // key->ipc_handle = packed->ipc_handle;

    *handle_p = NULL;
    *rkey_p = (uintptr_t)key;
    ucs_trace("unpacked rkey: key %p length  0x%"PRIx64" address %"PRIxPTR,
              key, key->length, key->address);
    return UCS_OK;
}
static ucs_status_t uct_rocm_rkey_release(uct_md_component_t *mdc, uct_rkey_t rkey,
                                          void *handle)
{
    ucs_assert(NULL == handle);
    ucs_free((void *)rkey);
    return UCS_OK;
}
static ucs_status_t uct_rocm_md_open(const char *md_name, const uct_md_config_t *md_config,
                                     uct_md_h *md_p)
{
    hsa_status_t   status;
    uct_rocm_md_t *rocm_md;


    static uct_md_ops_t md_ops = {
        .close        = uct_rocm_md_close,
        .query        = uct_rocm_md_query,
        .mkey_pack    = uct_rocm_rkey_pack,
        .mem_reg      = uct_rocm_mem_reg,
        .mem_dereg    = uct_rocm_mem_dereg
    };

    ucs_error("uct_rocm_md_open");

    status = hsa_init();

    if (HSA_STATUS_SUCCESS != status) {
        ucs_error("Failed to initialize HSA RT. HSA Status %d", status);
        return UCS_ERR_NO_RESOURCE;
    }

    rocm_md = ucs_malloc(sizeof(uct_rocm_md_t), "uct_rocm_md_t");
    if (NULL == rocm_md) {
        ucs_error("Failed to allocate memory for uct_rocm_md_t");
        return UCS_ERR_NO_MEMORY;
    }

    rocm_md->super.ops = &md_ops;
    rocm_md->super.component = &uct_rocm_md_component;

    *md_p = (uct_md_h)rocm_md;


    ucs_error("uct_rocm_md_open - success");
    return UCS_OK;
}

UCT_MD_COMPONENT_DEFINE(uct_rocm_md_component, UCT_ROCM_MD_NAME,
                        uct_rocm_query_md_resources, uct_rocm_md_open, 0,
                        uct_rocm_rkey_unpack,
                        uct_rocm_rkey_release, "ROCM_",
                        uct_md_config_table,
                        uct_md_config_t);
