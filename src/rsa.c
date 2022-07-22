/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT License. */

#include "log.h"
#include "pch.h"
#include "time.h"
#include "tokenmanager.h"

/**
 * @brief return the algorithm name for key vault or managed HSM for the given public key and hash algorithm
 * @see https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign
 *
 * @param ctx Public key context
 * @param sigmd signature hash algorithm
 * @return algorithm name == success, NULL == failure
 */
static char *ctx_to_alg(EVP_PKEY_CTX *ctx, const EVP_MD *sigmd)
{
    int mdType = EVP_MD_type(sigmd);
    log_debug( "   sigmd type=%d", mdType);

    int pad_mode = RSA_PKCS1_PADDING;
    if (EVP_PKEY_CTX_get_rsa_padding(ctx, &pad_mode) != 1)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_CANT_GET_PADDING);
        return NULL;
    }

    if (pad_mode != RSA_PKCS1_PADDING && pad_mode != RSA_PKCS1_PSS_PADDING)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_INVALID_PADDING);
        return NULL;
    }

    switch (mdType)
    {
    case NID_sha512:
        return pad_mode == RSA_PKCS1_PADDING ? "RS512" : "PS512";
    case NID_sha384:
        return pad_mode == RSA_PKCS1_PADDING ? "RS384" : "PS384";
    case NID_sha256:
        return pad_mode == RSA_PKCS1_PADDING ? "RS256" : "PS256";
    default:
        AKVerr(AKV_F_RSA_SIGN, AKV_R_UNSUPPORTED_KEY_ALGORITHM);
        return NULL;
    }
}

bool set;
// struct TokenManager v = {.accesstoken = "", .expiration = 0, .size=0}; 
// struct TokenManager m = {.accesstoken = "", .expiration = 0, .size=0};
struct TokenManager token_manager[2];

int akv_pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                      size_t *siglen, const unsigned char *tbs,
                      size_t tbslen)
{
    if (siglen == NULL)
    {
        log_error( "siglen is NULL\n");
        return 0;
    }

    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (!pkey)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_CANT_GET_KEY);
        return -1;
    }

    RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_INVALID_RSA);
        return -1;
    }

    if (!sig) {
        // OpenSSL may call this method without a sig array to
        // obtain the expected siglen value. This should be
        // treated as a successful call.
        *siglen = RSA_size(rsa);
        log_debug( "sig is null, setting siglen to [%zu]\n", *siglen);
        return 1;
    }

    AKV_KEY *akv_key = RSA_get_ex_data(rsa, rsa_akv_idx);
    if (!akv_key)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_CANT_GET_AKV_KEY);
        return -1;
    }

    const EVP_MD *sigmd = NULL;
    if (EVP_PKEY_CTX_get_signature_md(ctx, &sigmd) != 1)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_INVALID_MD);
        return 0;
    }

    // Don't support no padding.
    if (!sigmd)
    {
        AKVerr(AKV_F_RSA_SIGN, AKV_R_NO_PADDING);
        return 0;
    }

    const char *AKV_ALG = ctx_to_alg(ctx, sigmd);
    // log_debug( "-->akv_pkey_rsa_sign, tbs size [%zu], AKV_ALG [%s]", tbslen, AKV_ALG);
    log_error("TYPE OF ACCESS: %s", akv_key->keyvault_type);

    MemoryStruct accessToken;
    //0th index is vault, 1st index is hsm
    extern struct TokenManager token_manager[2];

    time_t current_time = time(NULL);
    log_info("current time: %d", current_time);
    extern bool set;
    if(set == false){
        // token_manager[0] = v;
        // token_manager[1] = m;
    } 

    //if there is no access token or if it is 10 seconds from expiring, request a new one
    //if((akv_key->keyvault_type == "vault" && (!token_manager[0].accesstoken || (token_manager[0].expiration - current_time) < 10)) || (akv_key->keyvault_type == "managedHsm" && (!token_manager[1].accesstoken || (token_manager[1].expiration - current_time) < 10))){
    // if((strcasecmp(akv_key->keyvault_type, "vault") == 0 && set == false) || (strcasecmp(akv_key->keyvault_type, "managedHsm") == 0 && set == false)){
    log_info("Value of set: %d", set);
    if(set == false){
        set = true;
        log_info("ENTERING IMDS FUNCTION!");
        if (!GetAccessTokenFromIMDS(akv_key->keyvault_type, &accessToken))
        {
            return 0;
        }
    }else{
        log_info("USING STORED VALUES!");
        if(strcasecmp(akv_key->keyvault_type, "vault") == 0){
            log_info("Before value of tokenmanager");
            log_info("Value of tokenmanager: %s", token_manager[0].accesstoken);
            accessToken.size = token_manager[0].size;
            log_info("before memory change");
            accessToken.memory = token_manager[0].accesstoken;
        }else{
            log_info("Before size in mhsm");
            accessToken.size = token_manager[1].size;
            accessToken.memory = token_manager[1].accesstoken;
        }
        log_info("Value of accesstoken after local copy: %s", accessToken.memory);
    }

    MemoryStruct signatureText;
    log_debug( "keyvault [%s][%s]", akv_key->keyvault_name, akv_key->key_name);
    if (AkvSign(akv_key->keyvault_type, akv_key->keyvault_name, akv_key->key_name, &accessToken, AKV_ALG, tbs, tbslen, &signatureText) == 1)
    {
        log_debug("Signed successfully signature.size=[%zu]\n", signatureText.size);

        if (*siglen == signatureText.size)
        {
            memcpy(sig, signatureText.memory, signatureText.size);
        }
        else
        {
            log_debug( "size prob = %zu\n", signatureText.size);
            *siglen = signatureText.size;
        }

        free(signatureText.memory);
        free(accessToken.memory);
        return 1;
    }
    else
    {
        log_error( "Failed to Sign\n");
        free(signatureText.memory);
        free(accessToken.memory);
        return 0;
    }
}

/**
 * @brief Return the algorithm name for key vault or managed HSM for the given padding mode
 * @see https://commondatastorage.googleapis.com/chromium-boringssl-docs/rsa.h.html#RSA_PKCS1_OAEP_PADDING
 * @param openssl_padding OpenSSL padding mode
 * @return Algorithm name == success, NULL == failure
 */
static char *padding_to_alg(int openssl_padding)
{
    log_debug( "   openssl_padding type=%d\n", openssl_padding);

    switch (openssl_padding)
    {
    case RSA_PKCS1_PADDING:
        return "RSA1_5"; // seems only RSA1_5 is working
    case RSA_PKCS1_OAEP_PADDING:
        return "RSA-OAEP"; //
    default:
        AKVerr(AKV_F_RSA_PRIV_DEC, AKV_R_INVALID_PADDING);
        return NULL;
    }
}

int akv_rsa_priv_dec(int flen, const unsigned char *from,
                     unsigned char *to, RSA *rsa, int padding)
{
    if (padding != RSA_PKCS1_PADDING && padding != RSA_PKCS1_OAEP_PADDING)
    {
        log_error( "   unsurported openssl_padding type=%d, only support RSA1_5 or RSA_OAEP \n", padding);
        return -1;
    }

    AKV_KEY *akv_key = NULL;
    const char *alg = padding_to_alg(padding);
    if (alg == NULL)
    {
        log_error( "   unsurported openssl_padding type=%d\n, only support RSA1_5 or RSA_OAEP", padding);
        return -1;
    }

    akv_key = RSA_get_ex_data(rsa, rsa_akv_idx);
    if (!akv_key)
    {
        AKVerr(AKV_F_RSA_PRIV_DEC, AKV_R_CANT_GET_AKV_KEY);
        return -1;
    }

    MemoryStruct accessToken;
    if (!GetAccessTokenFromIMDS(akv_key->keyvault_type, &accessToken))
    {
        return -1;
    }

    MemoryStruct clearText;
    if (AkvDecrypt(akv_key->keyvault_type, akv_key->keyvault_name, akv_key->key_name, &accessToken, alg, from, flen, &clearText) == 1)
    {
        log_debug( "Decrypt successfully clear text size=[%zu]\n", clearText.size);
        if (to != NULL)
        {
            memcpy(to, clearText.memory, clearText.size);
        }
        else
        {
            log_debug( "size probe, return [%zu]\n", clearText.size);
        }

        free(clearText.memory);
        free(accessToken.memory);
        return (int)clearText.size;
    }
    else
    {
        log_error( "Failed to decrypt\n");
        free(clearText.memory);
        free(accessToken.memory);
        return -1;
    }
}


int akv_rsa_priv_enc(int flen, const unsigned char *from,
                     unsigned char *to, RSA *rsa, int padding)
{
    if (padding != RSA_PKCS1_PADDING && padding != RSA_PKCS1_OAEP_PADDING)
    {
        log_error( "   unsurported openssl_padding type=%d, only support RSA1_5 or RSA_OAEP \n", padding);
        return -1;
    }

    AKV_KEY *akv_key = NULL;
    const char *alg = padding_to_alg(padding);
    if (alg == NULL)
    {
        log_error( "   unsurported openssl_padding type=%d\n, only support RSA1_5 or RSA_OAEP", padding);
        return -1;
    }

    akv_key = RSA_get_ex_data(rsa, rsa_akv_idx);
    if (!akv_key)
    {
        AKVerr(AKV_F_RSA_PRIV_DEC, AKV_R_CANT_GET_AKV_KEY);
        return -1;
    }

    MemoryStruct accessToken;
    if (!GetAccessTokenFromIMDS(akv_key->keyvault_type, &accessToken))
    {
        return -1;
    }

    MemoryStruct clearText;
    if (AkvEncrypt(akv_key->keyvault_type, akv_key->keyvault_name, akv_key->key_name, &accessToken, alg, from, flen, &clearText) == 1)
    {
        log_debug( "Decrypt successfully clear text size=[%zu]\n", clearText.size);
        if (to != NULL)
        {
            memcpy(to, clearText.memory, clearText.size);
        }
        else
        {
            log_debug( "size probe, return [%zu]\n", clearText.size);
        }

        free(clearText.memory);
        free(accessToken.memory);
        return (int)clearText.size;
    }
    else
    {
        log_error( "Failed to decrypt\n");
        free(clearText.memory);
        free(accessToken.memory);
        return -1;
    }
}
