/*
 * Copyright 2017 Advanced Micro Devices, Inc.
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

#include <uct/base/uct_log.h>

#include <hsa.h>
#include <hsa_ext_amd.h>


#include "rocm_common.h"

#include <pthread.h>

/** Mutex to guarantee that initialization will be atomic */
static pthread_mutex_t rocm_init_mutex = PTHREAD_MUTEX_INITIALIZER;


/** Max number of HSA agents supported */
#define MAX_HSA_AGENTS         64


/** Structure to keep all collected configuration info */
static struct {
    struct {
        struct {
            uint32_t                bus;    /**< PCI Bus id */
            uint32_t                device; /**< PCI Device id */
            uint32_t                func;   /**< PCI Function id */
            hsa_amd_memory_pool_t   pool;   /**< Global pool associated with agent.
                                              @note Current we assume that there
                                              is only one global pool per agent
                                              base on the current behaviour */
        } gpu_info[MAX_HSA_AGENTS];
        hsa_agent_t gpu_agent[MAX_HSA_AGENTS];/**< HSA GPU Agent handles */
        struct {
            hsa_agent_t           agent;    /**< HSA Agent handle for CPU */
            hsa_amd_memory_pool_t pool;     /**< Global pool associated with agent.
                                             @note Current we assume that there
                                             is only one global pool per agent
                                             base on the current behaviour */
        } cpu;
    } agents;
    int num_of_gpu;
} uct_rocm_cfg;

/** Flag to specify if ROCm UCX support was initialized or not */
static bool rocm_ucx_initialized;

/** Internal structure to store information about memory */
typedef struct {
    void                    *ptr;
    hsa_amd_pointer_info_t   info;
    uint32_t                 num_agents_accessible;
    hsa_agent_t              accessible[MAX_HSA_AGENTS];
} uct_rocm_ptr_t;


/** Callback to enumerate pools for given agent.
 *  Try to find global pool assuming one global pool per agent.
*/
static hsa_status_t uct_rocm_hsa_amd_memory_pool_callback(
                                hsa_amd_memory_pool_t memory_pool, void* data)
{
    hsa_status_t status;
    hsa_amd_segment_t amd_segment;

    status = hsa_amd_memory_pool_get_info(memory_pool,
                                         HSA_AMD_MEMORY_POOL_INFO_SEGMENT,
                                         &amd_segment);

    if (status != HSA_STATUS_SUCCESS) {
        ucs_error("Failure to get pool info: 0x%x", status);
        return status;
    }

    if (amd_segment ==  HSA_AMD_SEGMENT_GLOBAL) {
        *(hsa_amd_memory_pool_t *)data = memory_pool;
        ucs_debug("Found global pool: 0x%lx", memory_pool.handle);
        return HSA_STATUS_INFO_BREAK;
    }

    return HSA_STATUS_SUCCESS;
}

/** Callback to enumerate HSA agents */
static hsa_status_t uct_rocm_hsa_agent_callback(hsa_agent_t agent, void* data)
{
    uint32_t bdfid;
    hsa_device_type_t device_type;
    hsa_status_t status;

    ucs_debug("hsa_agent_callback: Agent  0x%lx", agent.handle);

    status = hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE, &device_type);

    if (status != HSA_STATUS_SUCCESS) {
        ucs_error("Failure to get device type: 0x%x", status);
        return status;
    }

    if (device_type == HSA_DEVICE_TYPE_GPU) {

        status = hsa_agent_get_info(agent, HSA_AMD_AGENT_INFO_BDFID, &bdfid);

        if (status != HSA_STATUS_SUCCESS) {
            ucs_warn("Failure to get pci info: 0x%x", status);
            return status;
        }

        uct_rocm_cfg.agents.gpu_agent[uct_rocm_cfg.num_of_gpu] = agent;
        uct_rocm_cfg.agents.gpu_info[uct_rocm_cfg.num_of_gpu].bus = (bdfid >> 8) & 0xff;
        uct_rocm_cfg.agents.gpu_info[uct_rocm_cfg.num_of_gpu].device = (bdfid >> 3) & 0x1F;
        uct_rocm_cfg.agents.gpu_info[uct_rocm_cfg.num_of_gpu].func = bdfid & 0x7;

        ucs_debug("Found GPU agent : 0x%lx. [ B#%02d, D#%02d, F#%02d ]",
                uct_rocm_cfg.agents.gpu_agent[uct_rocm_cfg.num_of_gpu].handle,
                uct_rocm_cfg.agents.gpu_info[uct_rocm_cfg.num_of_gpu].bus,
                uct_rocm_cfg.agents.gpu_info[uct_rocm_cfg.num_of_gpu].device,
                uct_rocm_cfg.agents.gpu_info[uct_rocm_cfg.num_of_gpu].func);


        uct_rocm_cfg.agents.gpu_info[uct_rocm_cfg.num_of_gpu].pool.handle
                                                            = (uint64_t) -1;
        status = hsa_amd_agent_iterate_memory_pools(agent,
                                    uct_rocm_hsa_amd_memory_pool_callback,
                                    &uct_rocm_cfg.agents.gpu_info[uct_rocm_cfg.num_of_gpu].pool);

        if (status != HSA_STATUS_SUCCESS && status != HSA_STATUS_INFO_BREAK) {
            ucs_error("Failure to iterate regions: 0x%x\n", status);
            return status;
        }

        if (uct_rocm_cfg.agents.gpu_info[uct_rocm_cfg.num_of_gpu].pool.handle
                                                    == (uint64_t)-1) {
            ucs_warn("Could not find memory pool for GPU agent");
        }

        uct_rocm_cfg.num_of_gpu++;

    } else  if (device_type == HSA_DEVICE_TYPE_CPU) {
        uct_rocm_cfg.agents.cpu.agent = agent;
        ucs_debug("Found CPU agent : 0x%lx", uct_rocm_cfg.agents.cpu.agent.handle);

        uct_rocm_cfg.agents.cpu.pool.handle = (uint64_t) -1;
        status = hsa_amd_agent_iterate_memory_pools(agent,
                                                    uct_rocm_hsa_amd_memory_pool_callback,
                                                    &uct_rocm_cfg.agents.cpu.pool);

        if (status != HSA_STATUS_SUCCESS && status != HSA_STATUS_INFO_BREAK) {
            ucs_error("Failure to iterate memory pools: 0x%x", status);
            return status;
        }

        if (uct_rocm_cfg.agents.cpu.pool.handle == (uint64_t)-1) {
            ucs_warn("Could not find memory pool for CPU agent");
        }
    }

    /* Keep iterating */
    return HSA_STATUS_SUCCESS;
}

/**
 * @brief Check if given agent is CPU one
 *
 * @param [in]  agent - \c [in]  HSA agent
 *
 * @return true  - if this CPU agent
 *         false - otherwise
*/
static bool uct_rocm_is_cpu_agent(hsa_agent_t agent)
{
    if (agent.handle != uct_rocm_cfg.agents.cpu.agent.handle)
        return true;
    else
        return false;
}
/**
 * @brief Check if given agent is GPU one
 *
 * @param [in]  agent - \c [in]  HSA agent
 *
 * @return true  - if this CPU agent
 *         false - otherwise
*/
static bool uct_rocm_is_gpu_agent(hsa_agent_t agent)
{
    return !uct_rocm_is_cpu_agent(agent);
}
/**
 * @brief Return default GPU agent to be used for copy/access operation
 *
 * @return GPU agent
 */
static hsa_agent_t uct_rocm_get_default_gpu_agent()
{
    return uct_rocm_cfg.agents.gpu_agent[0];
}
/**
 * @brief Find best already accessible GPU agent to be used for access
 *
 * @param  rocm_ptr - \c [in]  Pointer to structure describing memory
 *
 * @return  true if GPU agent was found
 *          false otherwise
*/
static bool uct_rocm_get_accessible_gpu_agent(uct_rocm_ptr_t *rocm_ptr, hsa_agent_t *gpu_agent)
{
    /* @note: Currently we returned the first found GPU agent which
     * may be incorrect in multi-GPU case from performance perspective.
     */
    int i;
    for (i=0; i < rocm_ptr->num_agents_accessible; i++) {
        if (uct_rocm_is_gpu_agent(rocm_ptr->accessible[i])) {
            *gpu_agent = rocm_ptr->accessible[i];
            return true;
        }
    }

    return false;
}
/**
 * @brief Try to find GPU agent which could be used for access to both memory
 * locations.
 *
 * @param [in]      ptr0  Structure describing the first location
 * @param [in]      ptr1  Structure describing the second location
 * @param [out]     Common GPU Agent if any
 *
 * @return  true  - GPU agent was found
 *          false - otherwise
 *
*/
static bool uct_rocm_find_common_gpu_agent(uct_rocm_ptr_t *ptr0,
                                           uct_rocm_ptr_t *ptr1,
                                           hsa_agent_t    *agent)
{
    int i, j;

    if (!ptr0->num_agents_accessible || !ptr0->num_agents_accessible) {
        ucs_trace("At least one allocation doesn't have any agents");
        return false;
    }


    for (i = 0; i <  ptr0->num_agents_accessible; i++) {

        if (ptr0->accessible[i].handle == uct_rocm_cfg.agents.cpu.agent.handle) {
            /* This is CPU agent. */
            continue;
        }

        if (uct_rocm_is_gpu_agent(ptr0->accessible[i])) {

            for (j = 0; j < ptr1->num_agents_accessible; j++) {
                if (ptr0->accessible[i].handle == ptr1->accessible[j].handle) {
                    *agent = ptr0->accessible[i];
                    ucs_trace("Found common GPU agent: 0x%lx", ptr0->accessible[i].handle);
                    return true;
                }
            }
        }
    }

    return false;
}

static void *alloc_callback(size_t _size) { return malloc(_size); }
/**
 * @brief Query information about pointer
 *
 * @param [in]   address    Pointer to allocation
 * @param [out]  ptr_info   Information describing pointer
 *
 * @return [out] HSA_STATUS_SUCCESS if operation was sucessful
 *               HSA error code otherwise
*/
static hsa_status_t uct_rocm_query_ptr_info(void *address, uct_rocm_ptr_t *rocm_ptr)
{
    hsa_status_t    status;
    hsa_agent_t    *accessible = NULL;

    ucs_trace("Query info for address %p", address);

    memset(rocm_ptr, 0, sizeof(uct_rocm_ptr_t));
    rocm_ptr->info.size = sizeof(hsa_amd_pointer_info_t);

    rocm_ptr->ptr                   = address; // Save address in structure
    rocm_ptr->num_agents_accessible = 0;

    status = hsa_amd_pointer_info(rocm_ptr->ptr, &rocm_ptr->info,
                                  alloc_callback,
                                  &rocm_ptr->num_agents_accessible,
                                  &accessible);

    if (status == HSA_STATUS_SUCCESS) {

        ucs_trace("Pointer type %d", rocm_ptr->info.type);
        ucs_trace("Pointer agentBaseAddress %p", rocm_ptr->info.agentBaseAddress);
        ucs_trace("Pointer hostBaseAddress %p", rocm_ptr->info.hostBaseAddress);
        ucs_trace("Pointer sizeInBytes  0x%lx", rocm_ptr->info.sizeInBytes);

        int i;
        for (i=0; i < rocm_ptr->num_agents_accessible; i++) {
            ucs_trace("Pointer accessible agent [%d] Accessible agent: 0x%lx",
                                            i, accessible[i].handle);
        }

        if (rocm_ptr->num_agents_accessible > MAX_HSA_AGENTS) {
            ucs_warn("Too many agents (%d) for address %p\n",
                        (int) rocm_ptr->num_agents_accessible, address);
            rocm_ptr->num_agents_accessible = ucs_min(rocm_ptr->num_agents_accessible, MAX_HSA_AGENTS);
        }

        memcpy(rocm_ptr->accessible, accessible,
                   sizeof(hsa_agent_t) * rocm_ptr->num_agents_accessible);

        free(accessible);

    } else {
        ucs_error("Could not query info for pointer %p. Status 0x%x", address, status);
    }

    return status;
}

hsa_status_t uct_rocm_init()
{
    hsa_status_t status;

    if (pthread_mutex_lock(&rocm_init_mutex) == 0) {
        if (rocm_ucx_initialized) {
            status =  HSA_STATUS_SUCCESS;
            goto end;
        }
    } else  {
        ucs_error("Could not take mutex");
        status = HSA_STATUS_ERROR;
        goto end;
    }

    /* Initialize HSA RT just in case if it was not initialized before */
    status = hsa_init();

    if (status != HSA_STATUS_SUCCESS) {
        ucs_error("Failure to open HSA connection: 0x%x", status);
        goto end;
    }

    /* Collect information about GPU agents */
    status = hsa_iterate_agents(uct_rocm_hsa_agent_callback, NULL);

    if (status != HSA_STATUS_SUCCESS && status != HSA_STATUS_INFO_BREAK) {
        ucs_error("Failure to iterate HSA agents: 0x%x", status);
        goto end;
    }

    rocm_ucx_initialized = true;

end:

    pthread_mutex_unlock(&rocm_init_mutex);
    return status;
}

bool uct_rocm_is_ptr_gpu_accessible(void *ptr, void **gpu_ptr)
{
    hsa_amd_pointer_info_t info;
    info.size = sizeof(hsa_amd_pointer_info_t);

    hsa_status_t status = hsa_amd_pointer_info(ptr, &info,
                                          NULL, NULL, NULL);

    if (status == HSA_STATUS_SUCCESS) {
        if (info.type != HSA_EXT_POINTER_TYPE_UNKNOWN) {

            if (gpu_ptr) {
                *gpu_ptr = info.agentBaseAddress;
            }

            ucs_trace("Address %p is GPU accessible (Agent addr %p)",
                       ptr, info.agentBaseAddress);

            return true;
        }
    }

    ucs_trace("Address %p is not GPU accessible", ptr);
    return false;
}

ssize_t uct_rocm_copy_memory(void *dst, void *src, size_t size)
{
    ssize_t         result = -1;
    uct_rocm_ptr_t  dst_ptr;
    uct_rocm_ptr_t  src_ptr;
    hsa_agent_t     src_agent;
    hsa_agent_t     dst_agent;
    hsa_agent_t     common_gpu_agent;
    hsa_signal_t    completion_signal;
    hsa_status_t    status;

    ucs_trace("Copy ROCm memory: dst %p, src %p, size 0x%lx", dst, src, size);

    /* Collect information about pointers */
    if (uct_rocm_query_ptr_info(dst, &dst_ptr) != HSA_STATUS_SUCCESS
        ||
        uct_rocm_query_ptr_info(src, &src_ptr) != HSA_STATUS_SUCCESS) {
        return result;
    }

   /* @todo: Add support for HSA_EXT_POINTER_TYPE_UNKNOWN memory
    * by locking it.
    */

    /* Assume that we deal only with memory which are known to HSA */

    /* For copy operation by GPU we need to pass GPU agents which has
     * access to the both: source and destination.
     * Unfortunately currently it is not possible to choose the best
     * GPU agent in the case of multi-GPUs due to the fact that we
     * do not have information where memory is physically located.
     */

    if (!uct_rocm_find_common_gpu_agent(&dst_ptr, &src_ptr, &common_gpu_agent)) {
          ucs_trace("There is no common GPU agents");

        if (!uct_rocm_get_accessible_gpu_agent(&src_ptr, &src_agent)) {
            if (uct_rocm_get_accessible_gpu_agent(&dst_ptr, &dst_agent)) {

                status = hsa_memory_assign_agent(src, dst_agent,
                                                 HSA_ACCESS_PERMISSION_RW);

                if (status != HSA_STATUS_SUCCESS) {
                    ucs_error("Failure to assign dst GPU agent to src. Status 0x%x", status);
                    goto end;
                }
            } else {
                /* We are not able to find any GPU agent for src and dst */
                src_agent = uct_rocm_get_default_gpu_agent();
                dst_agent = src_agent;

                status = hsa_memory_assign_agent(src, src_agent,
                                                 HSA_ACCESS_PERMISSION_RW);

                if (status != HSA_STATUS_SUCCESS) {
                    ucs_error("Failure to assign default GPU agent to src. Status 0x%x", status);
                    goto end;
                }

                status = hsa_memory_assign_agent(dst, dst_agent,
                                                 HSA_ACCESS_PERMISSION_RW);

                if (status != HSA_STATUS_SUCCESS) {
                    ucs_error("Failure to assign default GPU agent to dst. Status 0x%x", status);
                    goto end;
                }
            }
        } else {
            status = hsa_memory_assign_agent(dst, src_agent,
                                             HSA_ACCESS_PERMISSION_RW);

                if (status != HSA_STATUS_SUCCESS) {
                    ucs_error("Failure to assign src GPU agent to dst. Status 0x%x", status);
                    goto end;
                }
        }

    } else {
        ucs_trace("Found common GPU agents");
        src_agent = common_gpu_agent;
        dst_agent = common_gpu_agent;
    }

    /* Create a completion signal to wait for end of copy operation */
    status = hsa_signal_create(0, 0, NULL, &completion_signal);

    if (status != HSA_STATUS_SUCCESS) {
        ucs_error("Failed to create HSA signal.  Status 0xx%x", status);
        goto end;
    }

    /*  Set the completion signal value to 1 */
    hsa_signal_store_screlease(completion_signal, 1);

    /*  Perform an async copy  */
    status = hsa_amd_memory_async_copy(dst, dst_agent, src, src_agent, size,
                                    0, NULL, completion_signal);

    if (status != HSA_STATUS_SUCCESS) {
        ucs_error("Failure to async. copy.  Status 0x%x", status);
        goto destroy_signal;
    }

    /* Wait for completion */
    status = hsa_signal_wait_scacquire(completion_signal,
                                       HSA_SIGNAL_CONDITION_EQ,
                                       0, UINT64_MAX, HSA_WAIT_STATE_BLOCKED);

    if (status == HSA_STATUS_SUCCESS) {
        result = size;
    } else {
        ucs_error("Failure to wait copy completion.  Status 0x%x", status);
    }


destroy_signal:
    status = hsa_signal_destroy(completion_signal);
    if (status != HSA_STATUS_SUCCESS) {
        ucs_error("Failed to destroy signal.  Status 0x%x", status);
    }

end:
    return result;
}

hsa_status_t  uct_rocm_ipc_memory_attach(const hsa_amd_ipc_memory_t* handle,
                                      size_t len, void **ptr)
{

    hsa_status_t status = hsa_amd_ipc_memory_attach(handle,
                              len,
                              uct_rocm_cfg.num_of_gpu,
                              uct_rocm_cfg.agents.gpu_agent,
                              ptr);

   if (status != HSA_STATUS_SUCCESS) {
        ucs_error("hsa_amd_ipc_memory_attach failure. Status 0x%x", status);
   }

    return status;
}

void uct_rocm_ipc_memory_detach(void *ptr)
{
   hsa_status_t status = hsa_amd_ipc_memory_detach(ptr);

   if (status != HSA_STATUS_SUCCESS) {
        ucs_error("hsa_amd_ipc_memory_detach failure. Ptr %p. Status 0x%x",
                ptr, status);
   }
}

hsa_status_t uct_rocm_memory_lock(void *ptr, size_t size, void **gpu_ptr)
{
    /* We need to lock / register memory on all GPUs because we do not know
       the location of other memory */
    hsa_status_t status = hsa_amd_memory_lock(ptr, size,
                                             uct_rocm_cfg.agents.gpu_agent,
                                             uct_rocm_cfg.num_of_gpu,
                                             gpu_ptr
                                             );

    if (status != HSA_STATUS_SUCCESS) {
        ucs_error("Failed to lock memory (%p): 0x%x\n", ptr, status);
    }

    return status;
}
