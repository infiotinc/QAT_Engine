/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2016-2020 Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * ====================================================================
 */

/*
 * This file contains modified code from OpenSSL/BoringSSL used
 * in order to run certain operations in constant time.
 * It is subject to the following license:
 */

/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*****************************************************************************
 * @file qat_ipsec_aes.c
 *
 * This file contains the engine implementations for cipher operations
 *
 *****************************************************************************/

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <pthread.h>
#include <signal.h>
#ifdef USE_QAT_CONTIG_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "cmn_mem_drv_inf.h"
#endif

#include "qat_utils.h"
#include "e_qat.h"
#include "qat_callback.h"
#include "qat_polling.h"
#include "qat_events.h"
#include "e_qat_err.h"

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_sym.h"
#include "icp_sal_poll.h"
#include "qat_ciphers.h"
#include "qat_constant_time.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/tls1.h>
#include <openssl/async.h>
#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <string.h>

#ifdef OPENSSL_ENABLE_QAT_CIPHERS
# ifdef OPENSSL_DISABLE_QAT_CIPHERS
#  undef OPENSSL_DISABLE_QAT_CIPHERS
# endif
#endif

#define FLATBUFF_ALLOC_AND_CHAIN(b1, b2, len) \
                do { \
                    (b1).pData = qaeCryptoMemAlloc(len, __FILE__, __LINE__); \
                    (b2).pData = (b1).pData; \
                    (b1).dataLenInBytes = len; \
                    (b2).dataLenInBytes = len; \
                } while(0)

#define FLATBUFF_CHAIN_LEN(b1, b2, len) \
                do { \
                    (b1).dataLenInBytes = len; \
                    (b2).dataLenInBytes = len; \
                } while(0)

# define GET_SW_CIPHER(ctx) \
    qat_chained_cipher_sw_impl(EVP_CIPHER_CTX_nid((ctx)))


#define GET_SW_NON_CHAINED_CIPHER(ctx) \
    get_cipher_from_nid(EVP_CIPHER_CTX_nid((ctx)))

#define DEBUG_PPL DEBUG
#ifndef OPENSSL_DISABLE_QAT_CIPHERS

#define INF_ASYNC_PKT_SIZE  1500

#define IPSEC_ICV_LENGTH    12
#define IPSEC_QAT_ALIGNMENT 24
#define IPSEC_QAT_THRESHOLD 32

#define INF_ASYNC_MODE_BH   1 << 0
#define INF_ASYNC_MODE_CB   1 << 1

#define CB_QOP_QUEUE_MAX    16
#define CB_QOP_BURST_MAX    4

typedef struct _inf_app_data {
    u_int8_t    *iv;
    void        *cb_arg;
    int         (*cb_fn)(void*);
    void        *thunk;
} inf_app_data_t;

typedef struct _inf_op_done {
    /* Keep this as first member of the structure.
     * to allow inter-changeability by casting pointers.
     */
    op_done_t       opDone;
    volatile unsigned int num_pipes;
    volatile unsigned int num_submitted;
    volatile unsigned int num_processed;

    EVP_CIPHER_CTX  *ctx;
    int             ivlen;
    int             enc;
    int             mode;
    int             qctx_out_len;
    unsigned char   *qctx_out_src;
    unsigned char   *qctx_out_dst;
    unsigned char   *qctx_outb;
    qat_op_params   *qop;
    inf_app_data_t  app_data;
} inf_op_done_t;

typedef struct _inf_cb_stats {
    unsigned int    queue_full;
    unsigned int    queue_max;
    unsigned int    pull_max;
    unsigned int    submit_esess;
    unsigned int    submit_count;
    unsigned int    retry_count;
    unsigned int    callback_count;
    unsigned int    callback_bh;
    unsigned int    callback_eapp;
    unsigned int    callback_edepth;
    unsigned int    callback_eflag;
    unsigned int    callback_eproc;
    unsigned int    callback_etag;
    unsigned int    callback_done;
} inf_cb_stats_t;

inf_cb_stats_t      g_inf_cb_stats[2] = {0};

static int qat_chained_ipsec_ciphers_init(EVP_CIPHER_CTX *ctx,
                                    const unsigned char *inkey,
                                    const unsigned char *iv, int enc);
static int qat_chained_ipsec_ciphers_cleanup(EVP_CIPHER_CTX *ctx);
static int qat_chained_ipsec_ciphers_do_cipher(EVP_CIPHER_CTX *ctx,
                                         unsigned char *out,
                                         const unsigned char *in, size_t len);
static int qat_chained_ipsec_ciphers_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                    void *ptr);

static int qat_chained_ipsec_bottom_half(inf_op_done_t *cb_op_done);

static int qat_chained_ipsec_inst_num(int enc);

#endif

/* Setup template for Session Setup Data as most of the fields
 * are constant. The constant values of some of the fields are
 * chosen for Encryption operation.
 */
static const CpaCySymSessionSetupData template_ssd = {
    .sessionPriority = CPA_CY_PRIORITY_HIGH,
    .symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING,
    .cipherSetupData = {
                        .cipherAlgorithm = CPA_CY_SYM_CIPHER_AES_CBC,
                        .cipherKeyLenInBytes = 0,
                        .pCipherKey = NULL,
                        .cipherDirection = CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT,
                        },
    .hashSetupData = {
                      .hashAlgorithm = CPA_CY_SYM_HASH_SHA1,
                      .hashMode = CPA_CY_SYM_HASH_MODE_AUTH,
                      .digestResultLenInBytes = IPSEC_ICV_LENGTH,
                      .authModeSetupData = {
                                            .authKey = NULL,
                                            .authKeyLenInBytes = 0,
                                            },
                      },
    .algChainOrder = CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH,
    .digestIsAppended = CPA_FALSE,
    .verifyDigest = CPA_FALSE,
    .partialsNotRequired = CPA_TRUE,
};

static const CpaCySymOpData template_opData = {
    .sessionCtx = NULL,
    .packetType = CPA_CY_SYM_PACKET_TYPE_FULL,
    .pIv = NULL,
    .ivLenInBytes = 0,
    .cryptoStartSrcOffsetInBytes = QAT_BYTE_ALIGNMENT + IPSEC_QAT_ALIGNMENT,
    .messageLenToCipherInBytes = 0,
    .hashStartSrcOffsetInBytes = QAT_BYTE_ALIGNMENT,
    .messageLenToHashInBytes = 0,
    .pDigestResult = NULL,
};

static inline int get_digest_len(int nid)
{
    return IPSEC_ICV_LENGTH;
}

static inline const EVP_CIPHER *qat_chained_cipher_sw_impl(int nid)
{
    switch (nid) {
        case NID_aes_128_cbc:
            return EVP_aes_128_cbc();
        case NID_aes_256_cbc:
            return EVP_aes_256_cbc();
        default:
            WARN("Invalid nid %d\n", nid);
            return NULL;
    }
}

static inline const EVP_CIPHER *get_cipher_from_nid(int nid)
{
    switch (nid) {
        case NID_aes_128_cbc:
            return EVP_aes_128_cbc();
        case NID_aes_256_cbc:
            return EVP_aes_256_cbc();
        default:
            WARN("Invalid nid %d\n", nid);
            return NULL;
    }
}

CpaStatus qat_chained_ipsec_poll_instance(unsigned int inst_num)
{
    CpaStatus sts = CPA_STATUS_SUCCESS;
    int pull_count = 0;

    do {
        sts = icp_sal_CyPollInstance(qat_instance_handles[inst_num], 0);
        if (sts == CPA_STATUS_SUCCESS) {
            pull_count++;
        } else {
            g_inf_cb_stats[inst_num].retry_count++;
        }
        if (pull_count > g_inf_cb_stats[inst_num].pull_max) {
            g_inf_cb_stats[inst_num].pull_max = pull_count;
        }
    } while (sts == CPA_STATUS_SUCCESS);

    return sts;
}


static int qat_chained_ipsec_inst_num(int enc)
{
    int inst_num = QAT_INVALID_INSTANCE;
    thread_local_variables_t * tlv = NULL;
    int dec_inst = 0;
    int enc_inst = 1;

    tlv = qat_check_create_local_variables();
    if (unlikely(NULL == tlv)) {
        WARN("No local variables are available\n");
        return inst_num;
    }

    if (likely(qat_instance_handles && qat_num_instances)) {
        do {
            tlv->qatInstanceNumForThread = enc ? enc_inst : dec_inst;
        } while (!is_instance_available(tlv->qatInstanceNumForThread));
        inst_num = tlv->qatInstanceNumForThread;
    }

    /* If no working instance could be found then flag a warning */
    if (unlikely(inst_num == QAT_INVALID_INSTANCE)) {
        WARN("No working instance is available\n");
    }

    return inst_num;
}

static inline void qat_chained_ipsec_ciphers_free_qop(qat_op_params **pqop,
        unsigned int *num_elem)
{
    unsigned int i = 0;
    qat_op_params *qop = NULL;
    if (pqop != NULL && ((qop = *pqop) != NULL)) {
        for (i = 0; i < *num_elem; i++) {
            QAT_CHK_QMFREE_FLATBUFF(qop[i].src_fbuf[0]);
            QAT_CHK_QMFREE_FLATBUFF(qop[i].src_fbuf[1]);
            QAT_QMEMFREE_BUFF(qop[i].src_sgl.pPrivateMetaData);
            QAT_QMEMFREE_BUFF(qop[i].dst_sgl.pPrivateMetaData);
            QAT_QMEMFREE_BUFF(qop[i].op_data.pIv);
        }
        OPENSSL_free(qop);
        *pqop = NULL;
        *num_elem = 0;
    }
}

const EVP_CIPHER *qat_create_ipsec_cipher_meth(int nid, int keylen)
{
#ifndef OPENSSL_DISABLE_QAT_CIPHERS
    EVP_CIPHER *c = NULL;
    int res = 1;

    if ((c = EVP_CIPHER_meth_new(nid, AES_BLOCK_SIZE, keylen)) == NULL) {
        WARN("Failed to allocate cipher methods for nid %d\n", nid);
        return NULL;
    }

    res &= EVP_CIPHER_meth_set_iv_length(c, AES_IV_LEN);
    res &= EVP_CIPHER_meth_set_flags(c, QAT_CHAINED_FLAG);
    res &= EVP_CIPHER_meth_set_init(c, qat_chained_ipsec_ciphers_init);
    res &= EVP_CIPHER_meth_set_do_cipher(c, qat_chained_ipsec_ciphers_do_cipher);
    res &= EVP_CIPHER_meth_set_cleanup(c, qat_chained_ipsec_ciphers_cleanup);
    res &= EVP_CIPHER_meth_set_impl_ctx_size(c, sizeof(qat_chained_ctx));
    res &= EVP_CIPHER_meth_set_set_asn1_params(c, EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                               NULL : EVP_CIPHER_set_asn1_iv);
    res &= EVP_CIPHER_meth_set_get_asn1_params(c, EVP_CIPH_FLAG_DEFAULT_ASN1 ?
                                               NULL : EVP_CIPHER_get_asn1_iv);
    res &= EVP_CIPHER_meth_set_ctrl(c, qat_chained_ipsec_ciphers_ctrl);

    if (res == 0) {
        WARN("Failed to set cipher methods for nid %d\n", nid);
        EVP_CIPHER_meth_free(c);
        c = NULL;
    }

    return c;
#else
    return qat_chained_cipher_sw_impl(nid);
#endif
}

/******************************************************************************
* function:
*         qat_chained_callbackFn(void *callbackTag, CpaStatus status,
*                        const CpaCySymOp operationType, void *pOpData,
*                        CpaBufferList * pDstBuffer, CpaBoolean verifyResult)
*

* @param pCallbackTag  [IN] -  Opaque value provided by user while making
*                              individual function call. Cast to op_done_pipe_t.
* @param status        [IN] -  Status of the operation.
* @param operationType [IN] -  Identifies the operation type requested.
* @param pOpData       [IN] -  Pointer to structure with input parameters.
* @param pDstBuffer    [IN] -  Destination buffer to hold the data output.
* @param verifyResult  [IN] -  Used to verify digest result.
*
* description:
*   Callback function used by chained ciphers with pipeline support. This
*   function is called when operation is completed for each pipeline. However
*   the paused job is woken up when all the pipelines have been proccessed.
*
******************************************************************************/
static void qat_chained_ipsec_callbackFn(void *callbackTag, CpaStatus status,
                                   const CpaCySymOp operationType,
                                   void *pOpData, CpaBufferList *pDstBuffer,
                                   CpaBoolean verifyResult)
{
    ASYNC_JOB *job = NULL;
    inf_op_done_t *opdone = (inf_op_done_t *)callbackTag;
    CpaBoolean res = CPA_FALSE;
    int enc = opdone->enc;

    /* Callback issued */
    g_inf_cb_stats[enc].callback_count++;

    if (opdone == NULL) {
        WARN("Callback Tag NULL\n");
        g_inf_cb_stats[enc].callback_etag++;
        return;
    }

    opdone->num_processed++;

    res = (status == CPA_STATUS_SUCCESS) && verifyResult ? CPA_TRUE : CPA_FALSE;

    /* If any single pipe processing failed, the entire operation
     * is treated as failure. The default value of opDone.verifyResult
     * is TRUE. Change it to false on Failure.
     */
    if (res == CPA_FALSE) {
        WARN("Pipe %u failed (status %d, verifyResult %d)\n",
              opdone->num_processed, status, verifyResult);
        opdone->opDone.verifyResult = CPA_FALSE;
    }

    /* The QAT API guarantees submission order for request
     * i.e. first in first out. If not all requests have been
     * submitted or processed, wait for more callbacks.
     */
    if ((opdone->num_submitted != opdone->num_processed)) {
        g_inf_cb_stats[enc].callback_eproc++;
        return;
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_DEC(num_cipher_pipeline_requests_in_flight);
    }

    /* Cache job pointer to avoid a race condition if opdone gets cleaned up
     * in the calling thread.
     */
    job = (ASYNC_JOB *)opdone->opDone.job;

    /* Mark job as done when all the requests have been submitted and
     * subsequently processed.
     */
    opdone->opDone.flag = 1;

    if (job) {
       qat_wake_job(job, ASYNC_STATUS_OK);
    } else if (opdone-> mode & INF_ASYNC_MODE_CB) {
        qat_chained_ipsec_bottom_half(opdone);
    }
}

static int qat_init_cb_op_done(inf_op_done_t *opd)
{
    opd->num_pipes = 0;
    opd->num_submitted = 0;
    opd->num_processed = 0;
    opd->mode = INF_ASYNC_MODE_CB;

    opd->opDone.flag = 0;
    opd->opDone.verifyResult = CPA_TRUE;
    opd->opDone.job = NULL;

    return 1;
}


int qat_setup_cb_op_data(EVP_CIPHER_CTX *ctx, qat_op_params *qop)
{
    CpaCySymOpData *opd = NULL;
    qat_chained_ctx *qctx = qat_chained_data(ctx);
    opd = &qop->op_data;

    /* Update Opdata */
    opd->sessionCtx = qctx->session_ctx;

    if (!opd->sessionCtx) {
	    WARN("Failed to set session ctx\n");
        g_inf_cb_stats[qctx->inst_num].submit_esess++;
        return 0;
    }

    return 1;
}

/******************************************************************************
* function:
*         qat_setup_op_params(EVP_CIPHER_CTX *ctx)
*
* @param qctx    [IN]  - pointer to existing qat_chained_ctx
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function initialises the flatbuffer and flat buffer list for use.
*
******************************************************************************/
static int qat_setup_op_params(EVP_CIPHER_CTX *ctx, qat_op_params *qop)
{
    CpaCySymOpData *opd = NULL;
    qat_chained_ctx *qctx = qat_chained_data(ctx);
    Cpa32U msize = 0;

    FLATBUFF_ALLOC_AND_CHAIN(qop->src_fbuf[0],
                                qop->dst_fbuf[0], QAT_BYTE_ALIGNMENT);
    if (qop->src_fbuf[0].pData == NULL) {
        WARN("Unable to allocate memory for TLS header\n");
        goto err;
    }
    memset(qop->src_fbuf[0].pData, 0, QAT_BYTE_ALIGNMENT);

    qop->src_fbuf[1].pData = NULL;
    qop->dst_fbuf[1].pData = NULL;

    qop->src_sgl.numBuffers = 2;
    qop->src_sgl.pBuffers = qop->src_fbuf;
    qop->src_sgl.pUserData = NULL;
    qop->src_sgl.pPrivateMetaData = NULL;

    qop->dst_sgl.numBuffers = 2;
    qop->dst_sgl.pBuffers = qop->dst_fbuf;
    qop->dst_sgl.pUserData = NULL;
    qop->dst_sgl.pPrivateMetaData = NULL;

    /* setup meta data for buffer lists */
    if (msize == 0 &&
        cpaCyBufferListGetMetaSize(qat_instance_handles[qctx->inst_num],
                                    qop->src_sgl.numBuffers,
                                    &msize) != CPA_STATUS_SUCCESS) {
        WARN("cpaCyBufferListGetBufferSize failed.\n");
        goto err;
    }

    if (msize) {
        qop->src_sgl.pPrivateMetaData =
            qaeCryptoMemAlloc(msize, __FILE__, __LINE__);
        qop->dst_sgl.pPrivateMetaData =
            qaeCryptoMemAlloc(msize, __FILE__, __LINE__);
        if (qop->src_sgl.pPrivateMetaData == NULL ||
            qop->dst_sgl.pPrivateMetaData == NULL) {
            WARN("QMEM alloc failed for PrivateData\n");
            goto err;
        }
    }

    FLATBUFF_ALLOC_AND_CHAIN(qop->src_fbuf[1], qop->dst_fbuf[1], INF_ASYNC_PKT_SIZE);

    opd = &qop->op_data;

   /* Copy the opData template */
    memcpy(opd, &template_opData, sizeof(template_opData));

    opd->pIv = qaeCryptoMemAlloc(EVP_CIPHER_CTX_iv_length(ctx),
                                    __FILE__, __LINE__);
    if (opd->pIv == NULL) {
        WARN("QMEM Mem Alloc failed for pIv for Cb.\n");
        return 0;
    }

    opd->ivLenInBytes = (Cpa32U) EVP_CIPHER_CTX_iv_length(ctx);

    return 1;

err:
    return 0;
}

/******************************************************************************
* function:
*         qat_chained_ipsec_ciphers_init(EVP_CIPHER_CTX *ctx,
*                                    const unsigned char *inkey,
*                                    const unsigned char *iv,
*                                    int enc)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param inKey  [IN]  - input cipher key
* @param iv     [IN]  - initialisation vector
* @param enc    [IN]  - 1 encrypt 0 decrypt
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function initialises the cipher and hash algorithm parameters for this
*  EVP context.
*
******************************************************************************/
int qat_chained_ipsec_ciphers_init(EVP_CIPHER_CTX *ctx,
                             const unsigned char *inkey,
                             const unsigned char *iv, int enc)
{
    CpaCySymSessionSetupData *ssd = NULL;
    Cpa32U sctx_size = 0;
    CpaCySymSessionCtx sctx = NULL;
    CpaStatus sts = 0;
    qat_chained_ctx *qctx = NULL;
    unsigned char *ckey = NULL;
    int ckeylen;
    int dlen;
    int ret = 0;
    int i = 0;

    if (ctx == NULL || inkey == NULL) {
        WARN("ctx or inkey is NULL.\n");
        return 0;
    }

    qctx = qat_chained_data(ctx);
    if (qctx == NULL) {
        WARN("qctx is NULL.\n");
        return 0;
    }

    WARN("Initializing new QAT session %p/%p.\n", ctx, qctx);

    INIT_SEQ_CLEAR_ALL_FLAGS(qctx);

    if (iv != NULL)
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv,
               EVP_CIPHER_CTX_iv_length(ctx));
    else
        memset(EVP_CIPHER_CTX_iv_noconst(ctx), 0,
               EVP_CIPHER_CTX_iv_length(ctx));

    ckeylen = EVP_CIPHER_CTX_key_length(ctx);
    ckey = OPENSSL_malloc(ckeylen);
    if (ckey == NULL) {
        WARN("Unable to allocate memory for Cipher key.\n");
        return 0;
    }
    memcpy(ckey, inkey, ckeylen);

    memset(qctx, 0, sizeof(*qctx));

    qctx->numpipes = 1;
    qctx->total_op = 0;
    qctx->npipes_last_used = 1;
    qctx->fallback = 0;

    qctx->hmac_key = OPENSSL_zalloc(HMAC_KEY_SIZE);
    if (qctx->hmac_key == NULL) {
        WARN("Unable to allocate memory for HMAC Key\n");
        goto err;
    }

    const EVP_CIPHER *sw_cipher = GET_SW_CIPHER(ctx);
    unsigned int sw_size = EVP_CIPHER_impl_ctx_size(sw_cipher);
    if (sw_size != 0) {
        qctx->sw_ctx_cipher_data = OPENSSL_zalloc(sw_size);
        if (qctx->sw_ctx_cipher_data == NULL) {
            WARN("Unable to allocate memory [%u bytes] for sw_ctx_cipher_data\n",
                 sw_size);
            goto err;
        }
    }

    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
    /* Run the software init function */
    ret = EVP_CIPHER_meth_get_init(sw_cipher)(ctx, inkey, iv, enc);
    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
    if (ret != 1)
        goto err;
    if (qat_get_qat_offload_disabled()) {
        /*
         * Setting qctx->fallback as a flag for the other functions.
         * This means in the other functions (and in the err section in this function)
         * we no longer need to check qat_get_qat_offload_disabled() but just check
         * the fallback flag instead.  This has the added benefit that even if
         * the engine control message to enable HW offload is sent it will not affect
         * requests that have already been init'd, they will continue to use SW until
         * the request is complete, i.e. no race condition.
         */
        qctx->fallback = 1;
        goto err;
    }

    ssd = OPENSSL_malloc(sizeof(CpaCySymSessionSetupData));
    if (ssd == NULL) {
        WARN("Failed to allocate session setup data\n");
        goto err;
    }
    qctx->session_data = ssd;

    /* Copy over the template for most of the values */
    memcpy(ssd, &template_ssd, sizeof(template_ssd));

    /* Change constant values for decryption */
    if (!enc) {
        ssd->cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
        ssd->algChainOrder = CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER;
        ssd->verifyDigest = CPA_TRUE;
        ssd->digestIsAppended = CPA_TRUE;
    }

    ssd->cipherSetupData.cipherKeyLenInBytes = ckeylen;
    ssd->cipherSetupData.pCipherKey = ckey;

    dlen = get_digest_len(EVP_CIPHER_CTX_nid(ctx));

    ssd->hashSetupData.digestResultLenInBytes = dlen;

    ssd->hashSetupData.authModeSetupData.authKey = qctx->hmac_key;

    qctx->inst_num = qat_chained_ipsec_inst_num(enc);
    if (qctx->inst_num == QAT_INVALID_INSTANCE) {
        WARN("Failed to get a QAT instance.\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            qctx->fallback = 1;
        }
        goto err;
    }

    DEBUG("inst_num = %d\n", qctx->inst_num);
    DUMP_SESSION_SETUP_DATA(ssd);
    sts = cpaCySymSessionCtxGetSize(qat_instance_handles[qctx->inst_num], ssd, &sctx_size);

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("Failed to get SessionCtx size.\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                           qctx->inst_num,
                           qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
            qctx->fallback = 1;
        }
        goto err;
    }

    DEBUG("Size of session ctx = %d\n", sctx_size);
    sctx = (CpaCySymSessionCtx) qaeCryptoMemAlloc(sctx_size, __FILE__,
                                                  __LINE__);
    if (sctx == NULL) {
        WARN("QMEM alloc failed for session ctx!\n");
        goto err;
    }

    qctx->session_ctx = sctx;

    qctx->queue_depth = 0;
    qctx->qop_id = 0;
    qctx->qop_len = CB_QOP_QUEUE_MAX;
    qctx->qop = (qat_op_params *) OPENSSL_zalloc(sizeof(qat_op_params)
                                                    * qctx->qop_len);
    if (qctx->qop == NULL) {
        WARN("Unable to allocate memory[%lu bytes] for qat op params\n",
                sizeof(qat_op_params) * qctx->qop_len);
        goto err;
    }

    for (i = 0; i < qctx->qop_len; i++) {
        qat_setup_op_params(ctx, &qctx->qop[i]);
    }

    qctx->cop = (inf_op_done_t *) OPENSSL_zalloc(sizeof(inf_op_done_t)
                                                    * qctx->qop_len);

    if (qctx->cop == NULL) {
        WARN("Unable to allocate memory[%lu bytes] for qat cb params\n",
                sizeof(qat_op_params) * qctx->qop_len);
        goto err;
    }

    INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_QAT_CTX_INIT);

    DEBUG_PPL("[%p] qat chained cipher ctx %p initialised\n",ctx, qctx);
    return 1;

 err:
/* NOTE: no init seq flags will have been set if this 'err:' label code section is entered. */
    QAT_CLEANSE_FREE_BUFF(ckey, ckeylen);
    QAT_CLEANSE_FREE_BUFF(qctx->hmac_key, HMAC_KEY_SIZE);
    if (ssd != NULL)
        OPENSSL_free(ssd);
    qctx->session_data = NULL;
    QAT_QMEMFREE_BUFF(qctx->session_ctx);
    if ((qctx->fallback == 1) && (qctx->sw_ctx_cipher_data != NULL) && (ret == 1)) {
        DEBUG("- Fallback to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return ret; /* result returned from running software init function */
    }
    if (qctx->sw_ctx_cipher_data != NULL) {
        OPENSSL_free(qctx->sw_ctx_cipher_data);
        qctx->sw_ctx_cipher_data = NULL;
    }
    return 0;
}

/******************************************************************************
* function:
*    qat_chained_ipsec_ciphers_ctrl(EVP_CIPHER_CTX *ctx,
*                             int type, int arg, void *ptr)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param type   [IN]  - type of request either
*                       EVP_CTRL_AEAD_SET_MAC_KEY or EVP_CTRL_AEAD_TLS1_AAD
* @param arg    [IN]  - size of the pointed to by ptr
* @param ptr    [IN]  - input buffer contain the necessary parameters
*
* @retval x      The return value is dependent on the type of request being made
*       EVP_CTRL_AEAD_SET_MAC_KEY return of 1 is success
*       EVP_CTRL_AEAD_TLS1_AAD return value indicates the amount fo padding to
*               be applied to the SSL/TLS record
* @retval -1     function failed
*
* description:
*    This function is a generic control interface provided by the EVP API. For
*  chained requests this interface is used fro setting the hmac key value for
*  authentication of the SSL/TLS record. The second type is used to specify the
*  TLS virtual header which is used in the authentication calculationa nd to
*  identify record payload size.
*
******************************************************************************/
int qat_chained_ipsec_ciphers_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    qat_chained_ctx *qctx = NULL;
    unsigned char *hmac_key = NULL;
    CpaCySymSessionSetupData *ssd = NULL;
    int retVal = 0;
    int retVal_sw = 0;

    if (ctx == NULL) {
        WARN("ctx parameter is NULL.\n");
        return -1;
    }

    qctx = qat_chained_data(ctx);

    if (qctx == NULL) {
        WARN("qctx is NULL.\n");
        return -1;
    }

    if (qctx->fallback == 1)
        goto sw_ctrl;

    switch (type) {
        case EVP_CTRL_AEAD_SET_MAC_KEY:
            if (!INIT_SEQ_IS_FLAG_SET(qctx, INIT_SEQ_QAT_CTX_INIT)) {
                WARN("QAT Context not initialised");
                return -1;
            }
            hmac_key = qctx->hmac_key;
            ssd = qctx->session_data;

            memset(hmac_key, 0, HMAC_KEY_SIZE);
           /* IPSEC Auth Key Set */
            memcpy(hmac_key, ptr, arg);
            ssd->hashSetupData.authModeSetupData.authKeyLenInBytes = arg;
            return 1;

            /* All remaining cases are exclusive to pipelines and are not
             * used with small packet offload feature.
             */
        case EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS:
            if (arg > QAT_MAX_PIPELINES) {
                WARN("PIPELINE_OUTPUT_BUFS npipes(%d) > Max(%d).\n",
                     arg, QAT_MAX_PIPELINES);
                return -1;
            }
            qctx->p_out = (unsigned char **)ptr;
            qctx->numpipes = arg;
            INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_PPL_OBUF_SET);
            return 1;

        case EVP_CTRL_SET_PIPELINE_INPUT_BUFS:
            if (arg > QAT_MAX_PIPELINES) {
                WARN("PIPELINE_OUTPUT_BUFS npipes(%d) > Max(%d).\n",
                     arg, QAT_MAX_PIPELINES);
                return -1;
            }
            qctx->p_in = (unsigned char **)ptr;
            qctx->numpipes = arg;
            INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_PPL_IBUF_SET);
            return 1;

        case EVP_CTRL_SET_PIPELINE_INPUT_LENS:
            if (arg > QAT_MAX_PIPELINES) {
                WARN("PIPELINE_INPUT_LENS npipes(%d) > Max(%d).\n",
                     arg, QAT_MAX_PIPELINES);
                return -1;
            }
            qctx->p_inlen = (size_t *)ptr;
            qctx->numpipes = arg;
            INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_PPL_BUF_LEN_SET);
            return 1;

        default:
            WARN("Unknown type parameter\n");
            return -1;
    }

    /* Openssl EVP implementation changes the size of payload encoded in TLS
     * header pointed by ptr for EVP_CTRL_AEAD_TLS1_AAD, hence call is made
     * here after ptr has been processed by engine implementation.
     */
sw_ctrl:
    /* Currently, the s/w fallback feature does not support the use of pipelines.
     * However, even if the 'type' parameter passed in to this function implies
     * the use of pipelining, the s/w equivalent function (with this 'type' parameter)
     * will always be called if this 'sw_ctrl' label is reached.  If the s/w function
     * succeeds then, if fallback is set, this success is returned to the calling function.
     * If, however, the s/w function fails, then this s/w failure is always returned
     * to the calling function regardless of whether fallback is set. An example
     * would be multiple calls to this function with type == EVP_CTRL_AEAD_TLS1_AAD
     * such that qctx->aad_ctr becomes > 1, which would imply the use of pipelining.
     * These multiple calls are always made to the s/w equivalent function.
     */
    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
    retVal_sw = EVP_CIPHER_meth_get_ctrl(GET_SW_CIPHER(ctx))(ctx, type, arg, ptr);
    EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
    if ((qctx->fallback == 1) && (retVal_sw > 0)) {
        DEBUG("- Switched to software mode.\n");
        CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
        return retVal_sw;
    }
    if (retVal_sw <= 0) {
        WARN("s/w chained ciphers ctrl function failed.\n");
        return retVal_sw;
    }
    return retVal;
}


/******************************************************************************
* function:
*    qat_chained_ipsec_ciphers_cleanup(EVP_CIPHER_CTX *ctx)
*
* @param ctx    [IN]  - pointer to existing ctx
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function will cleanup all allocated resources required to perfrom the
*  cryptographic transform.
*
******************************************************************************/
int qat_chained_ipsec_ciphers_cleanup(EVP_CIPHER_CTX *ctx)
{
    qat_chained_ctx *qctx = NULL;
    CpaStatus sts = 0;
    CpaCySymSessionSetupData *ssd = NULL;
    int retVal = 1;
    int retry = 0;

    if (ctx == NULL) {
        WARN("ctx parameter is NULL.\n");
        return 0;
    }

    qctx = qat_chained_data(ctx);
    if (qctx == NULL) {
        WARN("qctx parameter is NULL.\n");
        return 0;
    }

    WARN("Clearing QAT session q(%d) %p/%p.\n", qctx->queue_depth , ctx, qctx);

    do {
        if (retry) {
            WARN("Draining qctx retry %d\n", retry);
            usleep(200000); /* 0.2 sec */
        }
        qat_chained_ipsec_poll_instance(qctx->inst_num);
        retry++;
    } while (qctx->queue_depth > 0 && retry < 3);

    if (qctx->sw_ctx_cipher_data != NULL) {
        OPENSSL_free(qctx->sw_ctx_cipher_data);
        qctx->sw_ctx_cipher_data = NULL;
    }

    /* ctx may be cleaned before it gets a chance to allocate qop */
    qat_chained_ipsec_ciphers_free_qop(&qctx->qop, &qctx->qop_len);
    OPENSSL_free(qctx->cop);

    ssd = qctx->session_data;
    if (ssd) {
        if (INIT_SEQ_IS_FLAG_SET(qctx, INIT_SEQ_QAT_SESSION_INIT)) {
            if (is_instance_available(qctx->inst_num)) {
                /* Clean up session if hardware available regardless of whether in */
                /* fallback or not, if in INIT_SEQ_QAT_SESSION_INIT */
                sts = cpaCySymRemoveSession(qat_instance_handles[qctx->inst_num],
                                            qctx->session_ctx);
                if (sts != CPA_STATUS_SUCCESS) {
                    WARN("cpaCySymRemoveSession FAILED, sts = %d\n", sts);
                    retVal = 0;
                }
            }
        }
        QAT_QMEMFREE_BUFF(qctx->session_ctx);
        QAT_CLEANSE_FREE_BUFF(ssd->hashSetupData.authModeSetupData.authKey,
                              ssd->hashSetupData.authModeSetupData.
                              authKeyLenInBytes);
        QAT_CLEANSE_FREE_BUFF(ssd->cipherSetupData.pCipherKey,
                              ssd->cipherSetupData.cipherKeyLenInBytes);
        OPENSSL_free(ssd);
    }

    qctx->fallback = 0;
    INIT_SEQ_CLEAR_ALL_FLAGS(qctx);
    DEBUG_PPL("[%p] EVP CTX cleaned up\n", ctx);
    return retVal;
}


/******************************************************************************
* function:
*    qat_chained_ipsec_ciphers_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
*                                  const unsigned char *in, size_t len)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param out   [OUT]  - output buffer for transform result
* @param in     [IN]  - input buffer
* @param len    [IN]  - length of input buffer
*
* @retval 0      function failed
* @retval 1      function succeeded
*
* description:
*    This function performs the cryptographic transform according to the
*  parameters setup during initialisation.
*
******************************************************************************/
int qat_chained_ipsec_ciphers_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                  const unsigned char *in, size_t len)
{
    CpaStatus sts = 0;
    CpaCySymOpData *opd = NULL;
    CpaBufferList *s_sgl = NULL;
    CpaBufferList *d_sgl = NULL;
    CpaFlatBuffer *s_fbuf = NULL;
    CpaFlatBuffer *d_fbuf = NULL;
    int retVal = 0, job_ret = 0;
    int pad_len = 0;
    int plen = 0;
    int plen_adj = 0;
    qat_chained_ctx *qctx = NULL;
    unsigned char *inb, *outb;
    unsigned int ivlen = 0;
    int dlen, enc, buflen;
    int discardlen = 0;
    int pipe = 0;
    int error = 0;
    int outlen = -1;
    thread_local_variables_t *tlv = NULL;
    inf_op_done_t  *cb_op_done = NULL;
    inf_app_data_t *app_data = NULL;

    if (ctx == NULL) {
        WARN("CTX parameter is NULL.\n");
        return -1;
    }

    qctx = qat_chained_data(ctx);
    if (qctx == NULL) {
        WARN("QAT CTX NULL\n");
        return -1;
    }


    while (qctx->queue_depth >= CB_QOP_QUEUE_MAX - 1) {
        g_inf_cb_stats[qctx->inst_num].queue_full++;
	    qat_chained_ipsec_poll_instance(qctx->inst_num);
    }

    if (qctx->fallback == 1)
        goto fallback;

    if (!(is_instance_available(qctx->inst_num))) {
        WARN("No QAT instance available.\n");
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
            qctx->fallback = 1;
            goto fallback;
        } else {
            WARN("Fail - No QAT instance available and s/w fallback is not enabled.\n");
            return -1; /* Fail if software fallback not enabled. */
        }
    } else {
        if (!INIT_SEQ_IS_FLAG_SET(qctx, INIT_SEQ_QAT_CTX_INIT)) {
            WARN("QAT Context not initialised");
            return -1;
        }
    }

    /* Pipeline initialisation requires multiple EVP_CIPHER_CTX_ctrl
     * calls to set all required parameters. Check if all have been
     * provided. For Pipeline, in and out buffers can be NULL as these
     * are supplied through ctrl messages.
     */
    if (PIPELINE_INCOMPLETE_INIT(qctx) ||
        (!PIPELINE_SET(qctx) && (out == NULL))) {
        WARN("%s \n",
             PIPELINE_INCOMPLETE_INIT(qctx) ?
             "Pipeline not initialised completely" : "out buffer null");
        return -1;
    }

    enc = EVP_CIPHER_CTX_encrypting(ctx);

    /* If we are encrypting and EVP_EncryptFinal_ex is called with a NULL
       input buffer then return 0. Note: we don't actually support partial
       requests in the engine but this workaround avoids an error from OpenSSL
       speed on the last request when measuring cipher performance. Speed is
       written to measure performance using partial requests.*/
    if (!PIPELINE_SET(qctx) &&
        in == NULL &&
        out != NULL &&
        enc) {
        DEBUG("QAT partial requests work-around: NULL input buffer passed.\n");
        return 0;
    }

    if (!INIT_SEQ_IS_FLAG_SET(qctx, INIT_SEQ_QAT_SESSION_INIT)) {
        /* The qat session is initialized when HMAC key is set. In case
         * HMAC key is not explicitly set, use default HMAC key of all zeros
         * and initialise a qat session.
         */

        DEBUG("inst_num = %d\n", qctx->inst_num);
        DUMP_SESSION_SETUP_DATA(qctx->session_data);
        DEBUG("session_ctx = %p\n", qctx->session_ctx);

        if (!(is_instance_available(qctx->inst_num))) {
            WARN("No QAT instance available so not initialising session.\n");
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Failed to get an instance - fallback to SW - %s\n", __func__);
                qctx->fallback = 1;
                goto fallback;
            } else {
                WARN("Fail - No QAT instance available and s/w fallback is not enabled.\n");
                return -1; /* Fail if software fallback not enabled. */
            }
        } else {
            sts = cpaCySymInitSession(qat_instance_handles[qctx->inst_num], qat_chained_ipsec_callbackFn,
                                      qctx->session_data, qctx->session_ctx);
            if (sts != CPA_STATUS_SUCCESS) {
                WARN("cpaCySymInitSession failed! Status = %d\n", sts);
                if (qat_get_sw_fallback_enabled() &&
                    ((sts == CPA_STATUS_RESTARTING) || (sts == CPA_STATUS_FAIL))) {
                    CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                                   qctx->inst_num,
                                   qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                                   __func__);
                    qctx->fallback = 1;
                    goto fallback;
                }
                else
                    return -1;
            }
            if (qat_get_sw_fallback_enabled()) {
                CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                               qctx->inst_num,
                               qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                               __func__);
            }
            INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_QAT_SESSION_INIT);
        }
    }

    if (error) {
        return -1;
    }

    ivlen = EVP_CIPHER_CTX_iv_length(ctx);
    dlen = get_digest_len(EVP_CIPHER_CTX_nid(ctx));

    /* Check and setup data structures for pipeline */
    if (PIPELINE_SET(qctx)) {
        /* All the aad data (tls header) should be present */
        if (qctx->aad_ctr != qctx->numpipes) {
            WARN("AAD data missing supplied %u of %u\n",
                 qctx->aad_ctr, qctx->numpipes);
            return -1;
        }
    } else {
#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
        if (len <= IPSEC_QAT_THRESHOLD) {
            EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
            retVal = EVP_CIPHER_meth_get_do_cipher(GET_SW_CIPHER(ctx))
                     (ctx, out, in, len);
            EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
            if (retVal) {
                outlen = len;
            }
            goto cleanup;
        }
#endif
        /* Add pad lne for HMAC */
        if (enc) {
            /* Set the payload length equal to entire length
             * of buffer i.e. there is no space for HMAC in
             * buffer.
             */
            plen = len;
            /* Find the extra length for qat buffers to store the HMAC and
             * padding which is later discarded when the result is copied out.
             * Note: AES_BLOCK_SIZE must be a power of 2 for this algorithm to
             * work correctly.
             * If the digest len (dlen) is a multiple of AES_BLOCK_SIZE, then
             * discardlen could theoretically be equal to 'dlen'.  However
             * 1 byte is still needed for the required pad_len field which would
             * not be available in this case.  Therefore we add an additional AES_BLOCK_SIZE to
             * ensure that even for the case of (dlen % AES_BLOCK_SIZE == 0) there
             * is room for the pad_len field byte - in this specific case the pad space
             * field would comprise the remaining 15 bytes and the pad_len byte field
             * would be equal to 15.
             * The '& ~(AES_BLOCK_SIZE - 1)' element of the algorithm serves to round down
             * 'discardlen' to the nearest AES_BLOCK_SIZE multiple.
             */
            discardlen = ((len + dlen + AES_BLOCK_SIZE) & ~(AES_BLOCK_SIZE - 1))
                - len;
            /* Pump-up the len by this amount */
            len += discardlen;
        }
        /* If the same ctx is being re-used for multiple invocation
         * of this function without setting EVP_CTRL for number of pipes,
         * the PIPELINE_SET is true from previous invocation. Clear Pipeline
         * when add_ctr is 1. This means user wants to switch from pipeline mode
         * to non-pipeline mode for the same ctx.
         */
        CLEAR_PIPELINE(qctx);

        /* setting these helps avoid decision branches when
         * pipelines are not used.
         */
        qctx->p_in = (unsigned char **)&in;
        qctx->p_out = &out;
        qctx->p_inlen = &len;
    }

#if 0
    DEBUG("[%p] Start Cipher operation with inst %u\n",
              ctx, qctx->inst_num);
#endif

    tlv = qat_check_create_local_variables();
    if (NULL == tlv) {
            WARN("could not create local variables\n");
            return -1;
    }

    QAT_INC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
    if (qat_use_signals()) {
        if (tlv->localOpsInFlight == 1) {
            if (qat_kill_thread(qat_timer_poll_func_thread, SIGUSR1) != 0) {
                WARN("qat_kill_thread error\n");
                QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
                return -1;
            }
        }
    }

    cb_op_done = &((inf_op_done_t*)qctx->cop)[qctx->qop_id];
    cb_op_done->qop = &qctx->qop[qctx->qop_id];
    qctx->qop_id = (qctx->qop_id + 1) % CB_QOP_QUEUE_MAX;
    if ((qat_init_cb_op_done(cb_op_done) != 1) ||
        (qat_setup_cb_op_data(ctx, cb_op_done->qop) != 1)) {
        WARN("Failure in qat_setup_op_params or qat_init_op_done_pipe\n");
        QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);
        return -1;
    }

    do {
        opd = &cb_op_done->qop->op_data;
        s_fbuf = cb_op_done->qop->src_fbuf;
        d_fbuf = cb_op_done->qop->dst_fbuf;
        s_sgl = &cb_op_done->qop->src_sgl;
        d_sgl = &cb_op_done->qop->src_sgl;
        inb = &qctx->p_in[pipe][0];
        outb = &qctx->p_out[pipe][0];
        buflen = qctx->p_inlen[pipe];

        if ((app_data = (inf_app_data_t*)EVP_CIPHER_CTX_get_app_data(ctx)) != NULL) {
            memcpy(opd->pIv, app_data->iv, ivlen);
            /* make a copy and free */
            memcpy(&cb_op_done->app_data, app_data, sizeof(inf_app_data_t));
        } else  {
            memcpy(opd->pIv, EVP_CIPHER_CTX_iv(ctx), ivlen);
        }

        /* Calculate payload and padding len */
        if (enc) {
            /* For non-TLS use case, plen has already been set above.
             */
            /* Compute the padding length using total buffer length, payload
             * length, digest length and a byte to encode padding len.
             */
            pad_len = buflen - (plen + dlen) - 1;

            /* If padlen is negative, then size of supplied output buffer
             * is smaller than required.
             */
            if ((buflen % AES_BLOCK_SIZE) != 0 || pad_len < 0 ||
                pad_len > TLS_MAX_PADDING_LENGTH) {
                WARN("buffer len[%d] or pad_len[%d] incorrect\n",
                     buflen, pad_len);
                error = 1;
                break;
            }
            opd->messageLenToCipherInBytes = len - discardlen - IPSEC_QAT_ALIGNMENT;
            opd->messageLenToHashInBytes = len - IPSEC_QAT_ALIGNMENT;
        } else {
            opd->messageLenToCipherInBytes = len - IPSEC_QAT_ALIGNMENT - IPSEC_ICV_LENGTH;
            opd->messageLenToHashInBytes = len - IPSEC_ICV_LENGTH;
        }


        FLATBUFF_CHAIN_LEN(s_fbuf[1], d_fbuf[1], buflen);

        memcpy(d_fbuf[1].pData, inb, buflen - discardlen);
        if (enc) {
            opd->pDigestResult = ((unsigned char*)d_fbuf[1].pData + len - IPSEC_QAT_ALIGNMENT);
        } else {
            opd->pDigestResult = ((unsigned char*)d_fbuf[1].pData + len);
        }

        DUMP_SYM_PERFORM_OP(qat_instance_handles[qctx->inst_num], opd, s_sgl, d_sgl);

        /* Increment prior to successful submission */
        cb_op_done->num_submitted++;

        cb_op_done->ctx = ctx;
        cb_op_done->ivlen = ivlen;
        cb_op_done->enc = enc;

        cb_op_done->qctx_out_len = len - discardlen - plen_adj + IPSEC_ICV_LENGTH;
        cb_op_done->qctx_out_dst = out + plen_adj;
        cb_op_done->qctx_out_src = cb_op_done->qop->dst_fbuf[1].pData;
        cb_op_done->qctx_outb = outb + buflen - discardlen - ivlen;

        g_inf_cb_stats[qctx->inst_num].submit_count++;
        qctx->queue_depth++;

        sts = qat_sym_perform_op(qctx->inst_num, cb_op_done, opd, s_sgl,
                                 d_sgl, &(qctx->session_data->verifyDigest));

        if (sts != CPA_STATUS_SUCCESS) {
            if (qat_get_sw_fallback_enabled() &&
                ((sts == CPA_STATUS_RESTARTING) || (sts == CPA_STATUS_FAIL))) {
                CRYPTO_QAT_LOG("Failed to submit request to qat inst_num %d device_id %d - fallback to SW - %s\n",
                               qctx->inst_num,
                               qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                               __func__);
                qctx->fallback = 1;
            }
            WARN("Failed to submit request to qat - status = %d\n", sts);
            error = 1;
            /* Decrement after failed submission */
            cb_op_done->num_submitted--;
            break;
        }
        if (qat_get_sw_fallback_enabled()) {
            CRYPTO_QAT_LOG("Submit success qat inst_num %d device_id %d - %s\n",
                           qctx->inst_num,
                           qat_instance_details[qctx->inst_num].qat_instance_info.physInstId.packageId,
                           __func__);
        }
    } while (++pipe < qctx->numpipes);

    /* If there is nothing to wait for, do not pause or yield */
    if (cb_op_done->num_submitted == 0 || (cb_op_done->num_submitted == cb_op_done->num_processed)) {
        if (cb_op_done->opDone.job != NULL) {
            qat_clear_async_event_notification();
        }
        goto end;
    }

    if (enable_heuristic_polling) {
        QAT_ATOMIC_INC(num_cipher_pipeline_requests_in_flight);
    }

    outlen = buflen + plen_adj - discardlen + IPSEC_ICV_LENGTH;

    if (cb_op_done-> mode & INF_ASYNC_MODE_CB) {
        if (qctx->queue_depth < CB_QOP_BURST_MAX)
        {
            return outlen;
        }

        qat_chained_ipsec_poll_instance(qctx->inst_num);
        return outlen;
    }


    do {
        if (cb_op_done->opDone.job != NULL) {
            /* If we get a failure on qat_pause_job then we will
               not flag an error here and quit because we have
               an asynchronous request in flight.
               We don't want to start cleaning up data
               structures that are still being used. If
               qat_pause_job fails we will just yield and
               loop around and try again until the request
               completes and we can continue. */
            if ((job_ret = qat_pause_job(cb_op_done->opDone.job, ASYNC_STATUS_OK)) == 0)
                pthread_yield();
        } else {
            qat_chained_ipsec_poll_instance(qctx->inst_num);
            pthread_yield();
        }
    } while (!cb_op_done->opDone.flag ||
             QAT_CHK_JOB_RESUMED_UNEXPECTEDLY(job_ret));
 end:
    QAT_DEC_IN_FLIGHT_REQS(num_requests_in_flight, tlv);

    qat_chained_ipsec_bottom_half(cb_op_done);


#ifndef OPENSSL_ENABLE_QAT_SMALL_PACKET_CIPHER_OFFLOADS
cleanup:
#endif
fallback:
    if (qctx->fallback == 1) {
        if (PIPELINE_SET(qctx)) {
            WARN("Pipelines are set when in s/w fallback mode, which is not supported.\n");
            return -1;
        } else {
            DEBUG("- Switched to software mode.\n");
            CRYPTO_QAT_LOG("Resubmitting request to SW - %s\n", __func__);
            EVP_CIPHER_CTX_set_cipher_data(ctx, qctx->sw_ctx_cipher_data);
            retVal = EVP_CIPHER_meth_get_do_cipher(GET_SW_CIPHER(ctx))
                (ctx, out, in, len);
            EVP_CIPHER_CTX_set_cipher_data(ctx, qctx);
            if (retVal)
                outlen = len;
        }
    }

    /* Reset the AAD counter forcing that new AAD information is provided
     * before each repeat invocation of this function.
     */
    qctx->aad_ctr = 0;

    /* This function can be called again with the same evp_cipher_ctx. */
    if (PIPELINE_SET(qctx)) {
        /* Number of pipes can grow between multiple invocation of this call.
         * Record the maximum number of pipes used so that data structures can
         * be allocated accordingly.
         */
        INIT_SEQ_CLEAR_FLAG(qctx, INIT_SEQ_PPL_AADCTR_SET);
        INIT_SEQ_SET_FLAG(qctx, INIT_SEQ_PPL_USED);
        qctx->npipes_last_used = qctx->numpipes > qctx->npipes_last_used
            ? qctx->numpipes : qctx->npipes_last_used;
    }
    return outlen;
}

int qat_chained_ipsec_bottom_half(inf_op_done_t *cb_op_done)
{
    EVP_CIPHER_CTX *ctx = cb_op_done->ctx;
    qat_chained_ctx *qctx = qat_chained_data(ctx);
    inf_app_data_t *app_data = &cb_op_done->app_data;
    int ivlen = cb_op_done->ivlen;
    CpaBufferList *d_sgl = &cb_op_done->qop->src_sgl;

    g_inf_cb_stats[qctx->inst_num].callback_bh++;

    if (qctx->queue_depth > 0) {
        qctx->queue_depth--;
    } else {
        g_inf_cb_stats[qctx->inst_num].callback_edepth++;
        if (g_inf_cb_stats[qctx->inst_num].callback_edepth % 100 == 0) {
            WARN("QUEUE DEPTH negative\n");
        }
    }

    if ( qctx->queue_depth > g_inf_cb_stats[qctx->inst_num].queue_max) {
        g_inf_cb_stats[qctx->inst_num].queue_max = qctx->queue_depth;
        WARN("QUEUE_MAX %d\n", g_inf_cb_stats[qctx->inst_num].queue_max);
    }

    if (cb_op_done->opDone.flag != 1 ||
        cb_op_done->opDone.verifyResult != CPA_TRUE) {
        /* Callback miss */
        WARN("QAT Callback miss\n");
        g_inf_cb_stats[qctx->inst_num].callback_eflag++;
        return 0;
    }

    DUMP_SYM_PERFORM_OP_OUTPUT(&(qctx->session_data->verifyDigest), d_sgl);

    memcpy(cb_op_done->qctx_out_dst,
            cb_op_done->qctx_out_src,
            cb_op_done->qctx_out_len);

    if (cb_op_done->enc)
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx),
               cb_op_done->qctx_outb, ivlen);

    qctx->total_op += cb_op_done->num_processed;

    if (app_data->cb_fn && app_data->cb_arg) {
        (*app_data->cb_fn)(app_data->cb_arg);
    } else {
        WARN("QAT app_data not found\n");
        g_inf_cb_stats[qctx->inst_num].callback_eapp++;
    }

    g_inf_cb_stats[qctx->inst_num].callback_done++;

    return 1;
}
