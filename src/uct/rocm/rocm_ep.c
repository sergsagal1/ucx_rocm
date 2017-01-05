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


#include "rocm_ep.h"
#include "rocm_ep.h"
#include "rocm_md.h"

#include <uct/base/uct_log.h>
#include <ucs/debug/memtrack.h>

#include "rocm_common.h"

static UCS_CLASS_INIT_FUNC(uct_rocm_ep_t, uct_iface_t *tl_iface,
                           const uct_device_addr_t *dev_addr,
                           const uct_iface_addr_t *iface_addr)
{
    uct_rocm_iface_t *iface = ucs_derived_of(tl_iface, uct_rocm_iface_t);
    UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super);

    return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_rocm_ep_t)
{
    /* No op */
}

UCS_CLASS_DEFINE(uct_rocm_ep_t, uct_base_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_rocm_ep_t, uct_ep_t, uct_iface_t*,
                          const uct_device_addr_t *, const uct_iface_addr_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_rocm_ep_t, uct_ep_t);


#define uct_rocm_trace_data(_remote_addr, _rkey, _fmt, ...) \
    ucs_trace_data(_fmt " to %"PRIx64"(%+ld)", ## __VA_ARGS__, (_remote_addr), \
                   (_rkey))


static inline ucs_status_t uct_rocm_copy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                        size_t iovcnt,  uint64_t remote_addr,
                                        uct_rocm_key_t *key, int put)
{
    ucs_trace("uct_rocm_copy: iovcnt %d remote_address %p, put %d",
             (int) iovcnt, (void*)remote_addr, put);

    ucs_trace("uct_rocm_copy: key = address  %p length 0x%lx",
                (void*)key->address, key->length);

    if (0 == iovcnt) {
        ucs_trace_data("Zero length request: ignore");
        return UCS_OK;
    }

    if (1 != iovcnt) {
        ucs_error("Invalid iovcnt. Must be 1. Passed : %d", (int) iovcnt);
        return UCS_ERR_INVALID_PARAM;
    }

    /* Import shared memory */

    ucs_assert(remote_addr == key->address);
    void *shared_ptr_local = NULL;
    hsa_status_t  status = uct_rocm_ipc_memory_attach(&key->ipc_handle,
                                                      key->length,
                                                      &shared_ptr_local);

    if (status != HSA_STATUS_SUCCESS) {
        ucs_error("Failed to import shared memory. Status: 0x%x", status);
        return UCS_ERR_INVALID_ADDR;
    }

    void     *local_base    = iov[0].buffer;
    size_t    length        = ucs_min(uct_iov_get_length(iov), key->length);

    void     *remote_base   = shared_ptr_local;

    ucs_trace("uct_rocm_zcopy: local_base[0] 0x%x remote_base[0] 0x%x",
                            *(int *)local_base, *(int *)remote_base);

    ssize_t copied;

     /* if put == 0 then, READ from the remote region into local one
      * if put == 1 then, WRITE to the remote region from local one
      */

    if (!put)
        copied = uct_rocm_copy_memory(local_base,  remote_base, length);
    else
        copied = uct_rocm_copy_memory(remote_base, local_base, length);

    if (copied < 0) {
        ucs_error("Delivered %zu instead of %zu", copied, length);
        uct_rocm_ipc_memory_detach(shared_ptr_local);
        return UCS_ERR_IO_ERROR;
    }

    ucs_trace("uct_rocm_copy: Copied %d", (int) copied);
    ucs_trace("uct_rocm_zcopy: local_base[0] 0x%x remote_base[0] 0x%x",
                            *(int *)local_base, *(int *)remote_base);

    uct_rocm_ipc_memory_detach(shared_ptr_local);
    return UCS_OK;
}



ucs_status_t uct_rocm_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov, size_t iovcnt,
                                   uint64_t remote_addr,  uct_rkey_t rkey,
                                   uct_completion_t *comp)
{
    uct_rocm_key_t *key = (uct_rocm_key_t *)rkey;
    ucs_status_t status;

    UCT_CHECK_IOV_SIZE(iovcnt, uct_rocm_iface_get_max_iov(), "uct_rocm_ep_put_zcopy");

    status = uct_rocm_copy(tl_ep, iov, iovcnt,  remote_addr, key, 1);
    UCT_TL_EP_STAT_OP_IF_SUCCESS(status, ucs_derived_of(tl_ep, uct_base_ep_t),
                                PUT, ZCOPY, uct_iov_total_length(iov, iovcnt));
    return status;
}


ucs_status_t uct_rocm_ep_get_zcopy(uct_ep_h tl_ep,  const uct_iov_t *iov, size_t iovcnt,
                                   uint64_t remote_addr, uct_rkey_t rkey,
                                   uct_completion_t *comp)
{
    uct_rocm_key_t *key = (uct_rocm_key_t *)rkey;
    ucs_status_t status;

    UCT_CHECK_IOV_SIZE(iovcnt, uct_rocm_iface_get_max_iov(), "uct_rocm_ep_put_zcopy");

    status = uct_rocm_copy(tl_ep, iov, iovcnt, remote_addr, key, 0);
    UCT_TL_EP_STAT_OP_IF_SUCCESS(status, ucs_derived_of(tl_ep, uct_base_ep_t),
                                 GET, ZCOPY, uct_iov_total_length(iov, iovcnt));
    return status;
}
