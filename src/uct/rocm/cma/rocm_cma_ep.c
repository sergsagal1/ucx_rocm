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


#include "rocm_cma_ep.h"
#include "rocm_cma_ep.h"
#include "rocm_cma_md.h"

#include <uct/base/uct_log.h>
#include <ucs/debug/memtrack.h>

#include <uct/sm/base/sm_iface.h>

#include <uct/rocm/base/rocm_common.h>

/* Include HSA Thunk header file */
#include <hsakmt.h>


/* Temporally definition of ROCm CMA API till it will be officially
   published
*/
#include <sys/uio.h>

ssize_t process_vm_readv(pid_t pid,
                                const struct iovec *local_iov,
                                unsigned long liovcnt,
                                const struct iovec *remote_iov,
                                unsigned long riovcnt,
                                unsigned long flags);

ssize_t process_vm_writev(pid_t pid,
                                 const struct iovec *local_iov,
                                 unsigned long liovcnt,
                                 const struct iovec *remote_iov,
                                 unsigned long riovcnt,
                                 unsigned long flags);

typedef struct _HsaMemoryRange {
	void               *MemoryAddress;   // Pointer to GPU memory
	HSAuint64          SizeInBytes;      // Size of above memory
} HsaMemoryRange;

HSAKMT_STATUS
HSAKMTAPI
hsaKmtProcessVMRead(
	pid_t                     Pid,                     // IN
	HsaMemoryRange            *LocalMemoryArray,       // IN
	HSAuint64                 LocalMemoryArrayCount,   // IN
	HsaMemoryRange            *RemoteMemoryArray,      // IN
	HSAuint64                 RemoteMemoryArrayCount,  // IN
	HSAuint64                 *SizeCopied              // OUT
)
{

    struct iovec local_iov[UCT_SM_MAX_IOV];
    struct iovec remote_iov;
    size_t i;

    for (i = 0; i < LocalMemoryArrayCount; i++) {
        local_iov[i].iov_base = LocalMemoryArray[i].MemoryAddress;
        local_iov[i].iov_len  = LocalMemoryArray[i].SizeInBytes;
    }

    remote_iov.iov_base = RemoteMemoryArray[0].MemoryAddress;
    remote_iov.iov_len  = RemoteMemoryArray[0].SizeInBytes;

    ssize_t ret = process_vm_readv(Pid, local_iov, i, &remote_iov, 1, 0);

    ucs_trace("hsaKmtProcessVMRead was called. Return %d\n", (int) ret);
    *SizeCopied = ret;

    return 0;
}

HSAKMT_STATUS
HSAKMTAPI
hsaKmtProcessVMWrite(
	pid_t                     Pid,                     // IN
	HsaMemoryRange            *LocalMemoryArray,       // IN
	HSAuint64                 LocalMemoryArrayCount,   // IN
	HsaMemoryRange            *RemoteMemoryArray,      // IN
	HSAuint64                 RemoteMemoryArrayCount,  // IN
	HSAuint64                 *SizeCopied              // OUT
)
{

    struct iovec local_iov[UCT_SM_MAX_IOV];
    struct iovec remote_iov;
    size_t i;

   //ucs_error("hsaKmtProcessVMWrite: LocalCount %d", (int) LocalMemoryArrayCount);

    for (i = 0; i < LocalMemoryArrayCount; i++) {
        local_iov[i].iov_base = LocalMemoryArray[i].MemoryAddress;
        local_iov[i].iov_len  = LocalMemoryArray[i].SizeInBytes;
        ucs_trace("hsaKmtProcessVMWrite:: iov_base %p len %d",
                   (void *)local_iov[i].iov_base, (int) local_iov[i].iov_len);
    }

    remote_iov.iov_base = RemoteMemoryArray[0].MemoryAddress;
    remote_iov.iov_len  = RemoteMemoryArray[0].SizeInBytes;
        ucs_trace("hsaKmtProcessVMWrite:: Remote iov_base %p len %d",
                   (void *)remote_iov.iov_base, (int) remote_iov.iov_len);

    ucs_trace("Copy: Remote pid: 0%x", Pid);
    ssize_t ret = process_vm_writev(Pid, local_iov,
                                   LocalMemoryArrayCount,
                                   &remote_iov, 1, 0);


    ucs_trace("hsaKmtProcessVMWrite was called. Return %d\n", (int) ret);
    *SizeCopied = ret;

    return 0;
}

/* ^^^^^^^^^^^^^^^^^^^ END OF TEMPORALLY CODE */

static UCS_CLASS_INIT_FUNC(uct_rocm_cma_ep_t, uct_iface_t *tl_iface,
                           const uct_device_addr_t *dev_addr,
                           const uct_iface_addr_t *iface_addr)
{
   uct_rocm_cma_iface_t *iface = ucs_derived_of(tl_iface, uct_rocm_cma_iface_t);
   UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super);

   self->remote_pid = *(const pid_t*)iface_addr;

   ucs_trace("uct_rocm_cma_ep init class. Interface address: 0x%x", self->remote_pid);

   return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_rocm_cma_ep_t)
{
    /* No op */
}

UCS_CLASS_DEFINE(uct_rocm_cma_ep_t, uct_base_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_rocm_cma_ep_t, uct_ep_t, uct_iface_t*,
                          const uct_device_addr_t *, const uct_iface_addr_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_rocm_cma_ep_t, uct_ep_t);


#define uct_rocm_cma_trace_data(_remote_addr, _rkey, _fmt, ...) \
    ucs_trace_data(_fmt " to %"PRIx64"(%+ld)", ## __VA_ARGS__, (_remote_addr), \
                   (_rkey))

ucs_status_t uct_rocm_cma_ep_common_zcopy(uct_ep_h tl_ep,
                                            const uct_iov_t *iov,
                                            size_t iovcnt,
                                            uint64_t remote_addr,
                                            uct_rocm_cma_key_t *key,
                                     HSAKMT_STATUS (*fn_p)(pid_t,
	                                                 HsaMemoryRange *,
	                                                 HSAuint64,
	                                                 HsaMemoryRange *,
	                                                 HSAuint64,
                                                     HSAuint64 *),
                                     char *fn_name)
{
    /* The logic was copied more/less verbatim from corresponding CMA zcopy
       function.
     */
    HSAuint64 delivered = 0;
    HSAuint64 SizeCopied;
    size_t iov_it;
    size_t iov_it_length;
    size_t iov_slice_length;
    size_t iov_slice_delivered;
    size_t local_iov_it;
    size_t length = 0;
    HsaMemoryRange local_iov[UCT_SM_MAX_IOV];
    HsaMemoryRange remote_iov;
    uct_rocm_cma_ep_t *ep = ucs_derived_of(tl_ep, uct_rocm_cma_ep_t);

    ucs_trace("uct_rocm_cma_ep_common_zcopy (%s): remote_addr: %p (gpu %p)",
                fn_name, (void *)remote_addr, (void*)key->address);

    do {
        iov_it_length = 0;
        local_iov_it = 0;
        for (iov_it = 0; iov_it < ucs_min(UCT_SM_MAX_IOV, iovcnt); ++iov_it) {
            iov_slice_delivered = 0;

            /* Get length of the particular iov element */
            iov_slice_length = uct_iov_get_length(iov + iov_it);

            /* Skip the iov element if no data */
            if (!iov_slice_length) {
                continue;
            }
            iov_it_length += iov_slice_length;

            if (iov_it_length <= delivered) {
                continue; /* Skip the iov element if transferred already */
            } else {
                /* Let's assume the iov element buffer can be delivered partially */
                if ((iov_it_length - delivered) < iov_slice_length) {
                    iov_slice_delivered = iov_slice_length - (iov_it_length - delivered);
                }
            }

            local_iov[local_iov_it].MemoryAddress = (void *)((char *)iov[iov_it].buffer +
                                                        iov_slice_delivered);
            local_iov[local_iov_it].SizeInBytes   = iov_slice_length - iov_slice_delivered;

            ++local_iov_it;
        }
        if (!delivered) {
            length = iov_it_length; /* Keep total length of the iov buffers */
        }

        if(!length) {
            return UCS_OK;          /* Nothing to deliver */
        }

        ucs_trace("Remote GPU Address %p, Remote Address %p",
                            (void *)key->address, (void *)remote_addr);
        /* Till Thunk finish support: use CPU address for testing */
        // remote_iov.MemoryAddress = (void *)(key->address + delivered);
        remote_iov.MemoryAddress = (void *)(remote_addr + delivered);

        remote_iov.SizeInBytes   = length - delivered;

        HSAKMT_STATUS status = fn_p(ep->remote_pid,
                                    local_iov, local_iov_it,
                                    &remote_iov, 1,
                                    &SizeCopied);

        if (status  != HSAKMT_STATUS_SUCCESS) {
            ucs_error("%s  copied  %zu instead of %zu, Status  %d",
                      fn_name, (ssize_t) SizeCopied, (ssize_t) length,
                      status);
            return UCS_ERR_IO_ERROR;
        }

        delivered += SizeCopied;
    } while (delivered < length);

    return UCS_OK;
}

ucs_status_t uct_rocm_cma_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov, size_t iovcnt,
                                  uint64_t remote_addr, uct_rkey_t rkey,
                                  uct_completion_t *comp)
{
    uct_rocm_cma_key_t *key = (uct_rocm_cma_key_t *)rkey;

    ucs_trace("uct_rocm_cma_ep_put_zcopy()");

    UCT_CHECK_IOV_SIZE(iovcnt, uct_sm_get_max_iov(), "uct_rocm_cma_ep_put_zcopy");

    ucs_status_t ret = uct_rocm_cma_ep_common_zcopy(tl_ep, iov,  iovcnt,
                                           remote_addr,
                                           key,
                                           hsaKmtProcessVMWrite,
                                           "hsaKmtProcessVMWrite");

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t), PUT, ZCOPY,
                      uct_iov_total_length(iov, iovcnt));
    uct_rocm_cma_trace_data(remote_addr, rkey, "PUT_ZCOPY [length %zu]",
                       uct_iov_total_length(iov, iovcnt));

    ucs_trace("uct_rocm_cma_ep_put_zcopy(). Status: 0x%x", ret);
    return ret;
}

ucs_status_t uct_rocm_cma_ep_get_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov, size_t iovcnt,
                                  uint64_t remote_addr, uct_rkey_t rkey,
                                  uct_completion_t *comp)
{
    uct_rocm_cma_key_t *key = (uct_rocm_cma_key_t *)rkey;

    ucs_trace("uct_rocm_cma_ep_get_zcopy()");

    UCT_CHECK_IOV_SIZE(iovcnt, uct_sm_get_max_iov(), "uct_rocm_cma_ep_get_zcopy");


    ucs_status_t ret = uct_rocm_cma_ep_common_zcopy(tl_ep, iov,  iovcnt,
                                                    remote_addr,
                                                    key,
                                                    hsaKmtProcessVMRead,
                                                    "hsaKmtProcessVMRead");

    UCT_TL_EP_STAT_OP(ucs_derived_of(tl_ep, uct_base_ep_t), GET, ZCOPY,
                      uct_iov_total_length(iov, iovcnt));
    uct_rocm_cma_trace_data(remote_addr, rkey, "GET_ZCOPY [length %zu]",
                       uct_iov_total_length(iov, iovcnt));

    ucs_trace("uct_rocm_cma_ep_get_zcopy(). Status: 0x%x", ret);

    return ret;
}
