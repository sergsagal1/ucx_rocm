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

#include "rocm_iface.h"
#include "rocm_md.h"
#include "rocm_ep.h"


#include <uct/base/uct_md.h>

// Note: Treat ROCM memory as the special case of shared memory.
#include <uct/sm/base/sm_iface.h>


UCT_MD_REGISTER_TL(&uct_rocm_md_component, &uct_rocm_tl);

static ucs_status_t uct_rocm_iface_query(uct_iface_h tl_iface,
                                         uct_iface_attr_t *iface_attr)
{
    memset(iface_attr, 0, sizeof(uct_iface_attr_t));
    ucs_trace("uct_rocm_iface_query");

    /* default values for all shared memory transports */

    iface_attr->cap.put.max_zcopy      = SIZE_MAX;
    iface_attr->cap.put.max_iov        = uct_rocm_iface_get_max_iov();

    iface_attr->cap.get.max_zcopy      = SIZE_MAX;
    iface_attr->cap.get.max_iov        = uct_rocm_iface_get_max_iov();

    iface_attr->cap.am.max_iov         = 1;


    iface_attr->iface_addr_len         = 0;
    iface_attr->device_addr_len        = sizeof(uint64_t);
    iface_attr->ep_addr_len            = 0;
    iface_attr->cap.flags              = UCT_IFACE_FLAG_GET_ZCOPY |
                                         UCT_IFACE_FLAG_PUT_ZCOPY |
                                         UCT_IFACE_FLAG_CONNECT_TO_IFACE;

    /**
     * @todo: Add logic to query ROCr about latency information.
     *
     * Question: How to handle/choose the correct one in the multi-GPUs case
     *           when latency could depends on source and target location?
     *
     */
    iface_attr->latency                = 80e-9; /* 80 ns */
    iface_attr->bandwidth              = 6911 * 1024.0 * 1024.0;
    iface_attr->overhead               = 50e-6; /* 50 us */

    return UCS_OK;
}

static UCS_CLASS_DECLARE_DELETE_FUNC(uct_rocm_iface_t, uct_iface_t);

static uct_iface_ops_t uct_rocm_iface_ops = {
    .iface_close         = UCS_CLASS_DELETE_FUNC_NAME(uct_rocm_iface_t),
    .iface_query         = uct_rocm_iface_query,
    .iface_get_address   = (void*)ucs_empty_function_return_success,
    .iface_get_device_address = uct_sm_iface_get_device_address,
    .iface_is_reachable  = uct_sm_iface_is_reachable,
    .iface_fence         = uct_sm_iface_fence,
    .ep_put_zcopy        = uct_rocm_ep_put_zcopy,
    .ep_get_zcopy        = uct_rocm_ep_get_zcopy,
    .ep_fence            = uct_sm_ep_fence,
    .ep_create_connected = UCS_CLASS_NEW_FUNC_NAME(uct_rocm_ep_t),
    .ep_destroy          = UCS_CLASS_DELETE_FUNC_NAME(uct_rocm_ep_t),
};


static UCS_CLASS_INIT_FUNC(uct_rocm_iface_t, uct_md_h md, uct_worker_h worker,
                           const uct_iface_params_t *params,
                           const uct_iface_config_t *tl_config)
{
    UCS_CLASS_CALL_SUPER_INIT(uct_base_iface_t, &uct_rocm_iface_ops, md, worker,
                              tl_config UCS_STATS_ARG(NULL));
    self->rocm_md = (uct_rocm_md_t *)md;


    return UCS_OK;
}


static UCS_CLASS_CLEANUP_FUNC(uct_rocm_iface_t)
{
    /* No OP */
}

UCS_CLASS_DEFINE(uct_rocm_iface_t, uct_base_iface_t);

static UCS_CLASS_DEFINE_NEW_FUNC(uct_rocm_iface_t, uct_iface_t, uct_md_h,
                                 uct_worker_h, const uct_iface_params_t*,
                                 const uct_iface_config_t *);
static UCS_CLASS_DEFINE_DELETE_FUNC(uct_rocm_iface_t, uct_iface_t);


static ucs_status_t uct_rocm_query_tl_resources(uct_md_h md,
                                                uct_tl_resource_desc_t **resource_p,
                                                unsigned *num_resources_p)
{

    /** @note Report the single device due to the complexity to deal with
     *        numerous agents (including GPUs cases) especially for
     *        p2p transfer cases.
     */

    uct_tl_resource_desc_t *resource;

    resource = ucs_calloc(1, sizeof(uct_tl_resource_desc_t), "ROCm resource desc");
    if (NULL == resource) {
        ucs_error("Failed to allocate memory");
        return UCS_ERR_NO_MEMORY;
    }

    ucs_snprintf_zero(resource->tl_name, sizeof(resource->tl_name), "%s",
                      UCT_ROCM_TL_NAME);
    ucs_snprintf_zero(resource->dev_name, sizeof(resource->dev_name), "%s",
                      md->component->name);

    /* Specify device type as "accelerator" device.*/
    resource->dev_type = UCT_DEVICE_TYPE_ACC;

    *num_resources_p = 1;
    *resource_p      = resource;

    return UCS_OK;
}

/**
 * Specify special environment variables to tune ROCm transport.
 * So far none but keep for future.
 */
static ucs_config_field_t uct_rocm_iface_config_table[] = {

    {"", "", NULL,
     ucs_offsetof(uct_rocm_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},

    {NULL}
};

UCT_TL_COMPONENT_DEFINE(uct_rocm_tl,
                        uct_rocm_query_tl_resources,
                        uct_rocm_iface_t,
                        UCT_ROCM_TL_NAME,
                        "ROCM_",
                        uct_rocm_iface_config_table,
                        uct_rocm_iface_config_t);

