/*******************************************************************************
 * Copyright 2017-2018, Schneider-Electric
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of tpm2-tss-engine nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <tss2/tss2_esys.h>

#include "tpm2-tss-engine.h"
#include "tpm2-tss-engine-common.h"

#define HANDLE_SIZE 8

typedef struct {
    TPM2_DATA *tpm2Data; // Key Data
    TPMI_YES_NO enc;     // Note: Openssl (encrypt:1) != TSS (encrypt:0)
    TPM2B_IV iv;         // Initialization Vector
} TPM2_DATA_CIPHER;

static TPM2B_DATA allOutsideInfo = {
    .size = 0,
};

static TPML_PCR_SELECTION allCreationPCR = {
    .count = 0,
};

static TPM2B_PUBLIC keyTemplate = {
    .publicArea = {
        .type = TPM2_ALG_SYMCIPHER,
        .nameAlg = ENGINE_HASH_ALG,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_SIGN_ENCRYPT |
                             TPMA_OBJECT_DECRYPT |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN |
                             TPMA_OBJECT_NODA),
        .authPolicy.size = 0,
        .parameters.symDetail.sym = {
             .algorithm = TPM2_ALG_NULL,
             .keyBits.sym = 0,
             .mode.sym = 0,
              },
        .unique.sym.size = 0
     }
};

static int tpm2_cipher_nids[] = {
    NID_aes_192_ofb128,
    NID_aes_256_cfb1,
    NID_aes_256_cbc,
    NID_aes_256_ofb128,
    NID_aes_256_cfb1,
    0
};

static int convert_array_hex_to_int(const unsigned char *in, size_t size)
{
    uint32_t integer = 0;

    for(size_t i = 0; i < size; i++)
    {
        integer |= in[i] << 8*(size - i - 1);
    }

    return integer;
}

int
tpm2tss_sym_genkey(EVP_CIPHER_CTX *cipher, TPMI_ALG_PUBLIC algo,
                   TPMI_ALG_SYM_MODE mode, int bits,
                   char *password, TPM2_HANDLE parentHandle)
{
    //DBG("Generating %s in %s mode for %i bits keysize.\n", algo, mode, bits);
    DBG("Generating for %i bits keysize.\n", bits);

    TSS2_RC r = TSS2_RC_SUCCESS;
    ESYS_AUXCONTEXT eactx = (ESYS_AUXCONTEXT) { 0 };
    ESYS_TR parent = ESYS_TR_NONE;
    TPM2B_PUBLIC *keyPublic = NULL;
    TPM2B_PRIVATE *keyPrivate = NULL;
    TPM2_DATA *tpm2Data = NULL;
    TPM2B_PUBLIC inPublic = keyTemplate;
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .sensitive = {
            .userAuth = {
                 .size = 0,
             },
            .data = {
                 .size = 0,
             }
        }
    };

    tpm2Data = OPENSSL_malloc(sizeof(*tpm2Data));
    if (tpm2Data == NULL) {
        ERR(tpm2tss_sym_genkey, TPM2TSS_R_GENERAL_FAILURE);
        goto error;
    }
    memset(tpm2Data, 0, sizeof(*tpm2Data));

    // Set mode, algo, keysize
    inPublic.publicArea.parameters.symDetail.sym.algorithm = algo;
    inPublic.publicArea.parameters.symDetail.sym.keyBits.sym = bits;
    inPublic.publicArea.parameters.symDetail.sym.mode.sym = mode;

    if (password) {
        DBG("Setting a password for the created key.\n");
        if (strlen(password) > sizeof(tpm2Data->userauth.buffer) - 1) {
            goto error;
        }
        tpm2Data->userauth.size = strlen(password);
        memcpy(&tpm2Data->userauth.buffer[0], password,
               tpm2Data->userauth.size);

        inSensitive.sensitive.userAuth.size = strlen(password);
        memcpy(&inSensitive.sensitive.userAuth.buffer[0], password,
               strlen(password));
    } else
        tpm2Data->emptyAuth = 1;

    r = init_tpm_parent(&eactx, parentHandle, &parent);
    ERRchktss(tpm2tss_sym_genkey, r, goto error);

    tpm2Data->parent = parentHandle;

    DBG("Generating the Sym key inside the TPM.\n");

    r = Esys_Create(eactx.ectx, parent,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitive, &inPublic, &allOutsideInfo, &allCreationPCR,
                    &keyPrivate, &keyPublic, NULL, NULL, NULL);
    ERRchktss(tpm2tss_sym_genkey, r, goto error);

    DBG("Generated the Sym key inside the TPM.\n");

    tpm2Data->pub = *keyPublic;
    tpm2Data->priv = *keyPrivate;

    EVP_CIPHER_CTX_set_app_data(cipher, tpm2Data);

    goto end;
 error:
    r = -1;
    if (tpm2Data)
        OPENSSL_free(tpm2Data);

 end:
    free(keyPrivate);
    free(keyPublic);

    if (parent != ESYS_TR_NONE && !parentHandle)
        Esys_FlushContext(eactx.ectx, parent);

    esys_auxctx_free(&eactx);

    return (r == TSS2_RC_SUCCESS);
}

static int populate_tpm2data(const unsigned char *key, TPM2_DATA **tpm2Data)
{
    uint32_t keyHandle = 0;

    /* Use an empty Key */
    if (key == NULL) {
        tpm2Data = NULL;

    /* Read persistent key, use for openssl API : EVP_EncryptInit_ex() */
    } else if (strncmp((char *)key, "0x81", 4) == 0) {
        sscanf((char *)key, "0x%x", &keyHandle);
        if (!tpm2tss_tpm2data_readtpm(keyHandle, tpm2Data))
            return 0;

    /* Read persistent key, use for openssl app : openssl enc */
    } else if ((key[0] == 0x81) && (key[HANDLE_SIZE/2 + 1] == 0)) {
        keyHandle = convert_array_hex_to_int(key, HANDLE_SIZE/2);
        if (!tpm2tss_tpm2data_readtpm(keyHandle, tpm2Data))
            return 0;

    /* Use blob context */
    } else {
        //if (!tpm2tss_tpm2data_read((char *)key, tpm2Data))
        //    return 0;
    }

    return 1;
}

static TPMI_ALG_SYM_MODE tpm2_get_cipher_mode(EVP_CIPHER_CTX *ctx, TPM2_DATA_CIPHER *tpm2DataCipher)
{
    if (tpm2DataCipher->tpm2Data->pub.publicArea.parameters.symDetail.sym.mode.sym == TPM2_ALG_NULL) {
        switch (EVP_CIPHER_CTX_mode(ctx)) {
            case EVP_CIPH_CFB_MODE:
                return TPM2_ALG_CFB;
            case EVP_CIPH_OFB_MODE:
                return TPM2_ALG_OFB;
            case EVP_CIPH_CTR_MODE:
                return TPM2_ALG_CTR;
            case EVP_CIPH_ECB_MODE:
                return TPM2_ALG_ECB;
            case EVP_CIPH_CBC_MODE:
                return TPM2_ALG_CBC;
            default:
                return TPM2_ALG_CBC;
        }
    } else {
        return tpm2DataCipher->tpm2Data->pub.publicArea.parameters.symDetail.sym.mode.sym;
    }
}

static int
tpm2_cipher_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    TPM2_DATA_CIPHER *tpm2DataCipher = NULL;

    DBG("Init Cipher Key ...\n");

    /* Init Struct */
    tpm2DataCipher = OPENSSL_malloc(sizeof(TPM2_DATA_CIPHER));
    if (tpm2DataCipher == NULL) {
        ERR(tpm2_cipher_init_key, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    memset(tpm2DataCipher, 0, sizeof(TPM2_DATA_CIPHER));

    /* Fill TPM2_DATA depending of KEY */
    if (!populate_tpm2data(key, &(tpm2DataCipher->tpm2Data))) {
        ERR(tpm2_cipher_init_key, TPM2TSS_R_TPM2DATA_READ_FAILED);
        goto error;
    }

    /* Fill IV */
    if (iv) {
        tpm2DataCipher->iv.size = EVP_CIPHER_CTX_iv_length(ctx);
        memcpy(tpm2DataCipher->iv.buffer, iv, tpm2DataCipher->iv.size);
    } else {
        tpm2DataCipher->iv.size = 0;
    }

    /* Fill ENC */
    tpm2DataCipher->enc = !enc;

    /* Set App Data */
    EVP_CIPHER_CTX_set_app_data(ctx, tpm2DataCipher);

    return 1;

error :
    if (tpm2DataCipher)
        OPENSSL_free(tpm2DataCipher);
    return 0;
}

static int
tpm2_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    TPM2_DATA_CIPHER *tpm2DataCipher;
    TSS2_RC ret;
    ESYS_AUXCONTEXT eactx = (ESYS_AUXCONTEXT){0};
    ESYS_TR keyHandle = ESYS_TR_NONE;
    TPM2B_MAX_BUFFER *out_data;
    TPM2B_MAX_BUFFER *in_data;
    TPM2B_IV *iv_out;
    TPM2B_IV iv_in;
    TPMI_ALG_SYM_MODE mode;
    TPMI_YES_NO enc;

    DBG("Ciphering ...\n");

    /* Get App Data */
    tpm2DataCipher = EVP_CIPHER_CTX_get_app_data(ctx);
    if (tpm2DataCipher == NULL ||  tpm2DataCipher->tpm2Data == NULL) {
        memcpy(out, in, inl);
        return 1;
    }

    /* Init TPM key */
    ret = init_tpm_key(&eactx, &keyHandle, tpm2DataCipher->tpm2Data);
    ERRchktss(tpm2_do_cipher, ret, goto error);

    /* Copy in_data : unsigned char* to TPM2B_MAX_BUFFER */
    in_data = OPENSSL_malloc(sizeof(TPM2B_MAX_BUFFER));
    if (tpm2DataCipher == NULL) {
        ERR(tpm2_do_cipher, ERR_R_MALLOC_FAILURE);
        goto error;
    }
    memcpy(in_data->buffer, in, inl);
    in_data->size = inl;

    /* Get mode value */
    mode = tpm2_get_cipher_mode(ctx, tpm2DataCipher);
    enc = tpm2DataCipher->enc;
    iv_in = tpm2DataCipher->iv;

    DBG("\n");
    DBG("algo : %#x\n", tpm2DataCipher->tpm2Data->pub.publicArea.parameters.symDetail.sym.algorithm);
    DBG("mode : %#x\n", mode);
    DBG("size : %d\n", tpm2DataCipher->tpm2Data->pub.publicArea.parameters.symDetail.sym.keyBits.sym);
    DBG("enc  : %d\n", enc);
    DBG("iv   : %d\n", iv_in.size);
    DBG("\n");

    /* Trying to encrypt */
    ret = Esys_EncryptDecrypt2( eactx.ectx,
                                keyHandle,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE,
                                ESYS_TR_NONE,
                                in_data,
                                enc,
                                mode,
                                &iv_in,
                                &out_data,
                                &iv_out );
    if (ret == TPM2_RC_COMMAND_CODE) {
        DBG("Esys_EncryptDecrypt2 : FAILED\n");
        ret = Esys_EncryptDecrypt( eactx.ectx,
                                   keyHandle,
                                   ESYS_TR_PASSWORD,
                                   ESYS_TR_NONE,
                                   ESYS_TR_NONE,
                                   enc,
                                   mode,
                                   &iv_in,
                                   in_data,
                                   &out_data,
                                   &iv_out );
        if(ret == TPM2_RC_SUCCESS) {
            DBG("Esys_EncryptDecrypt  : SUCCESS\n");
        }
        else {
            DBG("Esys_EncryptDecrypt  : FAILED\n");
        }
    }
    ERRchktss(tpm2_do_cipher, ret, goto error);

    /* Copy out_data : TPM2B_MAX_BUFFER to unsigned char* */
    memcpy(out, out_data->buffer, out_data->size);
    out[out_data->size] = '\0';

    /* Close TPM session */
    if (keyHandle != ESYS_TR_NONE) {
        if (tpm2DataCipher->tpm2Data->privatetype == KEY_TYPE_HANDLE) {
            Esys_TR_Close(eactx.ectx, &keyHandle);
        } else {
            Esys_FlushContext(eactx.ectx, keyHandle);
        }
    }
    esys_auxctx_free(&eactx);

    return 1;

error :
    /* Close TPM session */
    if (keyHandle != ESYS_TR_NONE) {
        if (tpm2DataCipher->tpm2Data->privatetype == KEY_TYPE_HANDLE) {
            Esys_TR_Close(eactx.ectx, &keyHandle);
        } else {
            Esys_FlushContext(eactx.ectx, keyHandle);
        }
    }
    esys_auxctx_free(&eactx);

    if (tpm2DataCipher)
        OPENSSL_free(tpm2DataCipher);
    return 0;
}

static int
tpm2_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    TPM2_DATA_CIPHER *tpm2DataCipher;

    DBG("Cleaning up ...\n");

    /* Free App Data */
    tpm2DataCipher = EVP_CIPHER_CTX_get_app_data(ctx);
    OPENSSL_free(tpm2DataCipher);
    EVP_CIPHER_CTX_set_app_data(ctx, NULL);

    return 1;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000
static EVP_CIPHER tpm2_aes_256_cbc =
{
    NID_aes_256_cbc,                    // ID
    TPM2_MAX_SYM_BLOCK_SIZE,            // Block size
    TPM2_MAX_SYM_KEY_BYTES,             // Key length
    TPM2_MAX_SYM_BLOCK_SIZE,            // IV length
    EVP_CIPH_CBC_MODE,                  // Flags
    tpm2_cipher_init_key,               // Init key
    tpm2_do_cipher,                     // Encrypt/Decrypt
    tpm2_cipher_cleanup,                // Cleanup
    sizeof(TPM2_DATA_CIPHER),           // Context size
    NULL,                               // Set ASN1 parameters
    NULL,                               // Get ASN1 parameters
    NULL,                               // CTRL
    NULL                                // App data
};
#else
static EVP_CIPHER *_tpm2_aes_256_cbc = NULL;
const EVP_CIPHER *tpm2_aes_256_cbc(void)
{
    if (_tpm2_aes_256_cbc == NULL &&
        ((_tpm2_aes_256_cbc = EVP_CIPHER_meth_new(NID_aes_256_cbc, TPM2_MAX_SYM_BLOCK_SIZE, TPM2_MAX_SYM_KEY_BYTES)) == NULL
         || !EVP_CIPHER_meth_set_iv_length(_tpm2_aes_256_cbc, TPM2_MAX_SYM_BLOCK_SIZE)
         || !EVP_CIPHER_meth_set_flags(_tpm2_aes_256_cbc, EVP_CIPH_CBC_MODE)
         || !EVP_CIPHER_meth_set_init(_tpm2_aes_256_cbc, tpm2_cipher_init_key)
         || !EVP_CIPHER_meth_set_do_cipher(_tpm2_aes_256_cbc, tpm2_do_cipher)
         || !EVP_CIPHER_meth_set_cleanup(_tpm2_aes_256_cbc, tpm2_cipher_cleanup)
         || !EVP_CIPHER_meth_set_impl_ctx_size(_tpm2_aes_256_cbc, sizeof(TPM2_DATA_CIPHER))
         || !EVP_CIPHER_meth_set_set_asn1_params(_tpm2_aes_256_cbc, NULL)
         || !EVP_CIPHER_meth_set_get_asn1_params(_tpm2_aes_256_cbc, NULL)
         || !EVP_CIPHER_meth_set_ctrl(_tpm2_aes_256_cbc, NULL)))
    {
        EVP_CIPHER_meth_free(_tpm2_aes_256_cbc);
        _tpm2_aes_256_cbc = NULL;
    }
    return _tpm2_aes_256_cbc;
}
#endif

static int
tpm2_ciphers_selector(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    (void)(e);
    int ret = 1;

    if (cipher == NULL) {
        *nids = tpm2_cipher_nids;
        return sizeof(tpm2_cipher_nids) / sizeof(tpm2_cipher_nids[0]) - 1;
    }

   switch (nid) {
    case NID_aes_256_cbc:
#if OPENSSL_VERSION_NUMBER < 0x10100000
        *cipher = &tpm2_aes_256_cbc;
#else
        *cipher = tpm2_aes_256_cbc();
#endif
        break;
    /*
    case NID_aes_256_ocb:
        *cipher = tpm2_aes_256_ocb();
        break;
    case NID_aes_256_cfb1:
        *cipher = tpm2_aes_256_cfb();
        break;
    */
    default:
        *cipher = NULL;
        ret = 0;
        break;
    }

    return ret;
}

int
init_ciphers(ENGINE *e)
{
    if (!ENGINE_set_ciphers(e, tpm2_ciphers_selector)) {
        DBG("ENGINE_set_ciphers failed\n");
        return 0;
    }

    return 1;
}
