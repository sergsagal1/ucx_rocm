/**
 * Copyright (c) UT-Battelle, LLC. 2014-2015. ALL RIGHTS RESERVED.
 * Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include <pmi.h>
#include "ucs/type/class.h"

#include <ucs/arch/cpu.h>
#include <uct/ugni/base/ugni_iface.h>
#include "ugni_smsg_iface.h"
#include "ugni_smsg_ep.h"

#define UCT_UGNI_SMSG_TL_NAME "ugni_smsg"

static ucs_config_field_t uct_ugni_smsg_iface_config_table[] = {
    {"", "ALLOC=huge,mmap,heap", NULL,
     ucs_offsetof(uct_ugni_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},

    UCT_IFACE_MPOOL_CONFIG_FIELDS("SMSG", -1, 0, "smsg",
                                  ucs_offsetof(uct_ugni_iface_config_t, mpool),
                                  "\nAttention: Setting this param with value != -1 is a dangerous thing\n"
                                  "and could cause deadlock or performance degradation."),

    {NULL}
};

static ucs_status_t progress_local_cq(uct_ugni_smsg_iface_t *iface){
    gni_return_t ugni_rc;
    gni_cq_entry_t event_data;
    uct_ugni_smsg_desc_t message_data;
    uct_ugni_smsg_desc_t *message_pointer;

    ugni_rc = GNI_CqGetEvent(iface->super.local_cq, &event_data);

    if(GNI_RC_NOT_DONE == ugni_rc){
        return UCS_OK;
    }

    if((GNI_RC_SUCCESS != ugni_rc && !event_data) || GNI_CQ_OVERRUN(event_data)){
        /* TODO: handle overruns */
        ucs_error("Error posting data. CQ overrun = %d", (int)GNI_CQ_OVERRUN(event_data));
        return UCS_ERR_NO_RESOURCE;
    }

    message_data.msg_id = GNI_CQ_GET_MSG_ID(event_data);
    message_pointer = sglib_hashed_uct_ugni_smsg_desc_t_find_member(iface->smsg_list,&message_data);
    ucs_assert(NULL != message_pointer);
    message_pointer->ep->outstanding--;
    iface->super.outstanding--;
    uct_ugni_ep_check_flush(message_pointer->ep);
    sglib_hashed_uct_ugni_smsg_desc_t_delete(iface->smsg_list,message_pointer);
    ucs_mpool_put(message_pointer);
    return UCS_INPROGRESS;
}

static void process_mbox(uct_ugni_smsg_iface_t *iface, uct_ugni_smsg_ep_t *ep){
    ucs_status_t status;
    uint8_t tag;
    void *data_ptr;
    gni_return_t ugni_rc;
    uct_ugni_smsg_header_t *header;
    void *user_data;

    pthread_mutex_lock(&uct_ugni_global_lock);

    while(1){
        tag = GNI_SMSG_ANY_TAG;
        ugni_rc = GNI_SmsgGetNextWTag(ep->super.ep, (void **)&data_ptr, &tag);

        /* Yes, GNI_RC_NOT_DONE means that you're done with the smsg mailbox */
        if(GNI_RC_NOT_DONE == ugni_rc){
            pthread_mutex_unlock(&uct_ugni_global_lock);
            return;
        }

        if(GNI_RC_SUCCESS != ugni_rc){
            ucs_error("Unhandled smsg error: %s %d", gni_err_str[ugni_rc], ugni_rc);
            pthread_mutex_unlock(&uct_ugni_global_lock);
            return;
        }

        if(NULL == data_ptr){
            ucs_error("Empty data pointer in smsg.");
            pthread_mutex_unlock(&uct_ugni_global_lock);
            return;
        }

        header = (uct_ugni_smsg_header_t *)data_ptr;
        user_data = (void *)(header + 1);

        uct_iface_trace_am(&iface->super.super, UCT_AM_TRACE_TYPE_RECV,
                           tag, user_data, header->length, "RX: AM");

        pthread_mutex_unlock(&uct_ugni_global_lock);
        status = uct_iface_invoke_am(&iface->super.super, tag, user_data,
                                     header->length, 0);
        pthread_mutex_lock(&uct_ugni_global_lock);

        ugni_rc = GNI_SmsgRelease(ep->super.ep);
        if(GNI_RC_SUCCESS != ugni_rc){
            ucs_error("Unhandled smsg error in GNI_SmsgRelease: %s %d", gni_err_str[ugni_rc], ugni_rc);
            pthread_mutex_unlock(&uct_ugni_global_lock);
            return;
        }
    }
}

static void uct_ugni_smsg_handle_remote_overflow(uct_ugni_smsg_iface_t *iface){
    gni_return_t ugni_rc;
    gni_cq_entry_t event_data;
    struct sglib_hashed_uct_ugni_ep_t_iterator ep_iterator;
    uct_ugni_ep_t *current_ep;
    uct_ugni_smsg_ep_t *ep;

    /* We don't know which EP dropped a completion entry, so flush everything */
    do{
        ugni_rc = GNI_CqGetEvent(iface->remote_cq, &event_data);
    } while(GNI_RC_NOT_DONE != ugni_rc);

    current_ep = sglib_hashed_uct_ugni_ep_t_it_init(&ep_iterator, iface->super.eps);

    while(NULL != current_ep){
        ep = ucs_derived_of(current_ep, uct_ugni_smsg_ep_t);
        process_mbox(iface, ep);
        current_ep = sglib_hashed_uct_ugni_ep_t_it_next(&ep_iterator);
    }
}

ucs_status_t progress_remote_cq(uct_ugni_smsg_iface_t *iface)
{
    gni_return_t ugni_rc;
    gni_cq_entry_t event_data;
    uct_ugni_ep_t tl_ep;
    uct_ugni_ep_t *ugni_ep;
    uct_ugni_smsg_ep_t *ep;

    ugni_rc = GNI_CqGetEvent(iface->remote_cq, &event_data);

    if(GNI_RC_NOT_DONE == ugni_rc){
        return UCS_OK;
    }

    if (GNI_RC_SUCCESS != ugni_rc || !GNI_CQ_STATUS_OK(event_data) || GNI_CQ_OVERRUN(event_data)) {
        if(GNI_RC_ERROR_RESOURCE == ugni_rc || (GNI_RC_SUCCESS == ugni_rc && GNI_CQ_OVERRUN(event_data))){
            ucs_debug("Detected remote CQ overrun. ungi_rc = %d [%s]", ugni_rc, gni_err_str[ugni_rc]);
            uct_ugni_smsg_handle_remote_overflow(iface);
            return UCS_OK;
        }
        ucs_error("GNI_CqGetEvent falied with unhandled error. Error status %s %d ",
                  gni_err_str[ugni_rc], ugni_rc);
        return UCS_ERR_IO_ERROR;
    }

    tl_ep.hash_key = GNI_CQ_GET_INST_ID(event_data);
    ugni_ep = sglib_hashed_uct_ugni_ep_t_find_member(iface->super.eps, &tl_ep);
    ep = ucs_derived_of(ugni_ep, uct_ugni_smsg_ep_t);

    process_mbox(iface, ep);
    return UCS_INPROGRESS;
}

UCS_CLASS_DEFINE_DELETE_FUNC(uct_ugni_smsg_iface_t, uct_iface_t);

static void uct_ugni_smsg_progress(void *arg)
{
    uct_ugni_smsg_iface_t *iface = (uct_ugni_smsg_iface_t *)arg;
    ucs_status_t status;

    do {
        status = progress_local_cq(iface);
    } while(status == UCS_INPROGRESS);
    do {
         status = progress_remote_cq(iface);
    } while(status == UCS_INPROGRESS);

    /* have a go a processing the pending queue */

    ucs_arbiter_dispatch(&iface->super.arbiter, iface->config.smsg_max_credit,
                         uct_ugni_ep_process_pending, NULL);
}

static void uct_ugni_smsg_iface_release_desc(uct_iface_t *tl_iface, void *desc)
{
    uct_ugni_smsg_desc_t *ugni_desc = ((uct_ugni_smsg_desc_t *)desc)-1;
    ucs_mpool_put(ugni_desc);
}

static ucs_status_t uct_ugni_smsg_query_tl_resources(uct_md_h md,
                                                     uct_tl_resource_desc_t **resource_p,
                                                     unsigned *num_resources_p)
{
    return uct_ugni_query_tl_resources(md, UCT_UGNI_SMSG_TL_NAME,
                                       resource_p, num_resources_p);
}

static ucs_status_t uct_ugni_smsg_iface_query(uct_iface_h tl_iface, uct_iface_attr_t *iface_attr)
{
    uct_ugni_smsg_iface_t *iface = ucs_derived_of(tl_iface, uct_ugni_smsg_iface_t);

    memset(iface_attr, 0, sizeof(uct_iface_attr_t));
    iface_attr->cap.am.max_short       = iface->config.smsg_seg_size-sizeof(uint64_t);
    iface_attr->cap.am.max_bcopy       = iface->config.smsg_seg_size;
    iface_attr->cap.am.opt_zcopy_align = 1;
    iface_attr->cap.am.align_mtu       = iface_attr->cap.am.opt_zcopy_align;
    iface_attr->device_addr_len        = sizeof(uct_devaddr_ugni_t);
    iface_attr->iface_addr_len         = sizeof(uct_sockaddr_ugni_t);
    iface_attr->ep_addr_len            = sizeof(uct_sockaddr_smsg_ugni_t);
    iface_attr->cap.flags              = UCT_IFACE_FLAG_AM_SHORT |
                                         UCT_IFACE_FLAG_AM_BCOPY |
                                         UCT_IFACE_FLAG_CONNECT_TO_EP |
                                         UCT_IFACE_FLAG_AM_CB_SYNC |
                                         UCT_IFACE_FLAG_PENDING;

    iface_attr->overhead               = 1e-6;  /* 1 usec */
    iface_attr->latency.overhead       = 40e-6; /* 40 usec */
    iface_attr->latency.growth         = 0;
    iface_attr->bandwidth              = pow(1024, 2); /* bytes */
    iface_attr->priority               = 0;
    return UCS_OK;
}


static UCS_CLASS_CLEANUP_FUNC(uct_ugni_smsg_iface_t)
{
    uct_worker_progress_unregister(self->super.super.worker,
                                   uct_ugni_smsg_progress, self);
    if (!self->super.activated) {
        return;
    }

    ucs_mpool_cleanup(&self->free_desc, 1);
    ucs_mpool_cleanup(&self->free_mbox, 1);
}

static ucs_status_t uct_ugni_smsg_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                              uct_completion_t *comp)
{
    uct_ugni_smsg_iface_t *iface = ucs_derived_of(tl_iface, uct_ugni_smsg_iface_t);
    ucs_status_t status;

    if (comp != NULL) {
        return UCS_ERR_UNSUPPORTED;
    }

    /* Always progress to local cq to get back send credits */
    status = progress_local_cq(iface);

    if (UCS_OK == status) {
        UCT_TL_IFACE_STAT_FLUSH(ucs_derived_of(tl_iface, uct_base_iface_t));
    } else {
        UCT_TL_IFACE_STAT_FLUSH_WAIT(ucs_derived_of(tl_iface, uct_base_iface_t));
    }

    return status;
}

static ucs_status_t uct_ugni_smsg_ep_flush(uct_ep_h tl_ep, unsigned flags,
                                           uct_completion_t *comp)
{
    uct_ugni_smsg_ep_t *ep = ucs_derived_of(tl_ep, uct_ugni_smsg_ep_t);
    ucs_status_t status;

    /* Even if we have no outstanding requests we can still get back send credits */
    status = progress_local_cq(ucs_derived_of(tl_ep->iface, uct_ugni_smsg_iface_t));

    if((0 == ep->super.outstanding) && (ep->super.arb_size == 0)) {
        ep->super.flush_flag = 0;
    }
    
    if(uct_ugni_can_flush(&ep->super)) {
        UCT_TL_EP_STAT_FLUSH(ucs_derived_of(tl_ep, uct_base_ep_t));
        status = UCS_OK;
    } else {
        ep->super.flush_flag = 1;
        UCT_TL_EP_STAT_FLUSH_WAIT(ucs_derived_of(tl_ep, uct_base_ep_t));
        status = UCS_ERR_NO_RESOURCE;
    }

    return status;
}

uct_iface_ops_t uct_ugni_smsg_iface_ops = {
    .iface_query           = uct_ugni_smsg_iface_query,
    .iface_flush           = uct_ugni_smsg_iface_flush,
    .iface_close           = UCS_CLASS_DELETE_FUNC_NAME(uct_ugni_smsg_iface_t),
    .iface_get_address     = uct_ugni_iface_get_address,
    .iface_get_device_address = uct_ugni_iface_get_dev_address,
    .iface_is_reachable    = uct_ugni_iface_is_reachable,
    .iface_release_desc    = uct_ugni_smsg_iface_release_desc,
    .ep_create             = UCS_CLASS_NEW_FUNC_NAME(uct_ugni_smsg_ep_t),
    .ep_get_address        = uct_ugni_smsg_ep_get_address,
    .ep_connect_to_ep      = uct_ugni_smsg_ep_connect_to_ep,
    .ep_destroy            = UCS_CLASS_DELETE_FUNC_NAME(uct_ugni_smsg_ep_t),
    .ep_pending_add        = uct_ugni_ep_pending_add,
    .ep_pending_purge      = uct_ugni_ep_pending_purge,
    .ep_am_short           = uct_ugni_smsg_ep_am_short,
    .ep_am_bcopy           = uct_ugni_smsg_ep_am_bcopy,
    .ep_flush              = uct_ugni_smsg_ep_flush,
};

static ucs_status_t ugni_smsg_activate_iface(uct_ugni_smsg_iface_t *iface)
{
    ucs_status_t status;
    gni_return_t ugni_rc;
    uint32_t pe_address;

    if(iface->super.activated) {
        return UCS_OK;
    }
    /*pull out these chunks into common routines */
    status = uct_ugni_init_nic(0, &iface->super.domain_id,
                               &iface->super.cdm_handle, &iface->super.nic_handle,
                               &pe_address);
    if (UCS_OK != status) {
        ucs_error("Failed to UGNI NIC, Error status: %d", status);
        return status;
    }

    ugni_rc = GNI_CqCreate(iface->super.nic_handle, UCT_UGNI_LOCAL_CQ, 0,
                           GNI_CQ_NOBLOCK,
                           NULL, NULL, &iface->super.local_cq);
    if (GNI_RC_SUCCESS != ugni_rc) {
        ucs_error("GNI_CqCreate failed, Error status: %s %d",
                  gni_err_str[ugni_rc], ugni_rc);
        return UCS_ERR_NO_DEVICE;
    }

    ugni_rc = GNI_CqCreate(iface->super.nic_handle, 40000, 0,
                           GNI_CQ_NOBLOCK,
                           NULL, NULL, &iface->remote_cq);

    if (GNI_RC_SUCCESS != ugni_rc) {
        ucs_error("GNI_CqCreate failed, Error status: %s %d",
                  gni_err_str[ugni_rc], ugni_rc);
        return UCS_ERR_NO_DEVICE;
    }

    iface->super.activated = true;

    /* iface is activated */
    return UCS_OK;
}

static ucs_status_t ugni_smsg_deactivate_iface(uct_ugni_smsg_iface_t *iface)
{
    gni_return_t ugni_rc;

    if(!iface->super.activated) {
        return UCS_OK;
    }

    ugni_rc = GNI_CqDestroy(iface->super.local_cq);
    if (GNI_RC_SUCCESS != ugni_rc) {
        ucs_warn("GNI_CqDestroy failed, Error status: %s %d",
                 gni_err_str[ugni_rc], ugni_rc);
        return UCS_ERR_IO_ERROR;
    }

    ugni_rc = GNI_CqDestroy(iface->remote_cq);
    if (GNI_RC_SUCCESS != ugni_rc) {
        ucs_warn("GNI_CqDestroy failed, Error status: %s %d",
                 gni_err_str[ugni_rc], ugni_rc);
        return UCS_ERR_IO_ERROR;
    }

    ugni_rc = GNI_CdmDestroy(iface->super.cdm_handle);
    if (GNI_RC_SUCCESS != ugni_rc) {
        ucs_warn("GNI_CdmDestroy error status: %s (%d)",
                 gni_err_str[ugni_rc], ugni_rc);
        return UCS_ERR_IO_ERROR;
    }

    iface->super.activated = false ;
    return UCS_OK;
}

static ucs_mpool_ops_t uct_ugni_smsg_desc_mpool_ops = {
    .chunk_alloc   = ucs_mpool_hugetlb_malloc,
    .chunk_release = ucs_mpool_hugetlb_free,
    .obj_init      = uct_ugni_base_desc_init,
    .obj_cleanup   = NULL
};

static ucs_mpool_ops_t uct_ugni_smsg_mbox_mpool_ops = {
    .chunk_alloc   = ucs_mpool_chunk_mmap,
    .chunk_release = ucs_mpool_chunk_munmap,
    .obj_init      = NULL,
    .obj_cleanup   = NULL
};

static UCS_CLASS_INIT_FUNC(uct_ugni_smsg_iface_t, uct_md_h md, uct_worker_h worker,
                           const uct_iface_params_t *params,
                           const uct_iface_config_t *tl_config)
{
    uct_ugni_iface_config_t *config = ucs_derived_of(tl_config, uct_ugni_iface_config_t);
    ucs_status_t status;
    gni_return_t ugni_rc;
    unsigned int bytes_per_mbox;
    gni_smsg_attr_t smsg_attr;

    pthread_mutex_lock(&uct_ugni_global_lock);

    UCS_CLASS_CALL_SUPER_INIT(uct_ugni_iface_t, md, worker, params,
                              &uct_ugni_smsg_iface_ops,
                              &config->super UCS_STATS_ARG(NULL));

    /* Setting initial configuration */
    self->config.smsg_seg_size = 2048;
    self->config.rx_headroom  = params->rx_headroom;
    self->config.smsg_max_retransmit = 16;
    self->config.smsg_max_credit = 8;
    self->smsg_id = 0;

    smsg_attr.msg_type = GNI_SMSG_TYPE_MBOX_AUTO_RETRANSMIT;
    smsg_attr.mbox_maxcredit = self->config.smsg_max_credit;
    smsg_attr.msg_maxsize = self->config.smsg_seg_size;

    ugni_rc = GNI_SmsgBufferSizeNeeded(&(smsg_attr), &bytes_per_mbox);
    self->bytes_per_mbox = ucs_align_up_pow2(bytes_per_mbox, ucs_get_page_size());

    if (ugni_rc != GNI_RC_SUCCESS) {
        ucs_error("Smsg buffer size calculation failed");
        status = UCS_ERR_INVALID_PARAM;
        goto exit;
    }

    status = ucs_mpool_init(&self->free_desc,
                            0,
                            self->config.smsg_seg_size + sizeof(uct_ugni_smsg_desc_t),
                            0,
                            UCS_SYS_CACHE_LINE_SIZE,      /* alignment */
                            128           ,               /* grow */
                            config->mpool.max_bufs,       /* max buffers */
                            &uct_ugni_smsg_desc_mpool_ops,
                            "UGNI-SMSG-DESC");

    if (UCS_OK != status) {
        ucs_error("Desc Mpool creation failed");
        goto exit;
    }

    status = ucs_mpool_init(&self->free_mbox,
                            0,
                            self->bytes_per_mbox + sizeof(uct_ugni_smsg_mbox_t),
                            sizeof(uct_ugni_smsg_mbox_t),
                            UCS_SYS_CACHE_LINE_SIZE,      /* alignment */
                            128,                          /* grow */
                            config->mpool.max_bufs,       /* max buffers */
                            &uct_ugni_smsg_mbox_mpool_ops,
                            "UGNI-SMSG-MBOX");

    if (UCS_OK != status) {
        ucs_error("Mbox Mpool creation failed");
        goto clean_desc;
    }

    status = ugni_smsg_activate_iface(self);
    if (UCS_OK != status) {
        ucs_error("Failed to activate the interface");
        goto clean_mbox;
    }

    ugni_rc = GNI_SmsgSetMaxRetrans(self->super.nic_handle, self->config.smsg_max_retransmit);

    if (ugni_rc != GNI_RC_SUCCESS) {
        ucs_error("Smsg setting max retransmit count failed.");
        status = UCS_ERR_INVALID_PARAM;
        goto clean_iface;
    }

    /* TBD: eventually the uct_ugni_progress has to be moved to
     * udt layer so each ugni layer will have own progress */
    uct_worker_progress_register(worker, uct_ugni_smsg_progress, self);
    pthread_mutex_unlock(&uct_ugni_global_lock);
    return UCS_OK;

 clean_iface:
    ugni_smsg_deactivate_iface(self);
 clean_desc:
    ucs_mpool_cleanup(&self->free_desc, 1);
 clean_mbox:
    ucs_mpool_cleanup(&self->free_mbox, 1);
 exit:
    ucs_error("Failed to activate interface");
    pthread_mutex_unlock(&uct_ugni_global_lock);
    return status;
}

UCS_CLASS_DEFINE(uct_ugni_smsg_iface_t, uct_ugni_iface_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_ugni_smsg_iface_t, uct_iface_t, uct_md_h,
                          uct_worker_h, const uct_iface_params_t*,
                          const uct_iface_config_t *);

UCT_TL_COMPONENT_DEFINE(uct_ugni_smsg_tl_component,
                        uct_ugni_smsg_query_tl_resources,
                        uct_ugni_smsg_iface_t,
                        UCT_UGNI_SMSG_TL_NAME,
                        "UGNI_SMSG",
                        uct_ugni_smsg_iface_config_table,
                        uct_ugni_iface_config_t);

UCT_MD_REGISTER_TL(&uct_ugni_md_component, &uct_ugni_smsg_tl_component);
