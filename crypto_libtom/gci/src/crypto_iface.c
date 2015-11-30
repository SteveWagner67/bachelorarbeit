#include "crypto_iface.h"

GciResult_t gci_init(const uint8_t* user, size_t userLen, const uint8_t* password, size_t passLen)
{
	return GCI_OK;
}



GciResult_t gci_deinit(void)
{
	return GCI_OK;
}


GciResult_t gci_get_info(GciInfo_t infoType, uint8_t* info, size_t* infoLen)
{
	return GCI_OK;
}


GciResult_t gci_ctx_release(GciCtxId_t ctxID)
{
	return GCI_OK;
}


GciResult_t gci_hash_new_ctx(GciHashAlgo_t hashAlgo, GciCtxId_t* ctxID)
{
	return GCI_OK;
}

GciResult_t gci_hash_ctx_clone(GciCtxId_t idSrc, GciCtxId_t* idDest)
{
	return GCI_OK;
}


GciResult_t gci_hash_update(GciCtxId_t ctxID, const uint8_t* blockMsg, size_t blockLen)
{
	return GCI_OK;
}

GciResult_t gci_hash_finish(GciCtxId_t ctxID, uint8_t* digest, size_t* digestLen)
{
	return GCI_OK;
}

GciResult_t gci_sign_new_ctx(const GciSignConfig_t* signConfig, GciKeyId_t keyID, GciCtxId_t* ctxID)
{
	return GCI_OK;
}

GciResult_t gci_sign_ctx_clone(GciCtxId_t idSrc, GciCtxId_t* idDest)
{
	return GCI_OK;
}


GciResult_t gci_sign_update(GciCtxId_t ctxID,const uint8_t* blockMsg, size_t blockLen)
{
	return GCI_OK;
}


GciResult_t gci_sign_gen_finish(GciCtxId_t ctxID, uint8_t* sign, size_t* signLen)
{
	return GCI_OK;
}


GciResult_t gci_sign_verify_finish(GciCtxId_t ctxID, const uint8_t* sign, size_t signLen)
{
	return GCI_OK;
}

GciResult_t gci_key_pair_gen(const GciKeyGenConfig_t* keyConfig, size_t keyLen, GciKeyId_t* pubKeyID, GciKeyId_t* privKeyID)
{
	return GCI_OK;
}

GciResult_t gci_cipher_new_ctx(const GciCipherConfig_t* ciphConfig, GciKeyId_t keyID, GciCtxId_t* ctxID)
{
	return GCI_OK;
}

GciResult_t gci_cipher_encrypt(GciCtxId_t ctxId, const uint8_t* plaintxt, size_t pltxtLen, uint8_t* ciphtxt, size_t* cptxtLen)
{
	return GCI_OK;
}

GciResult_t gci_cipher_decrypt(GciCtxId_t ctxId, const uint8_t* ciphtxt, int cptxtLen, uint8_t* plaintxt, size_t* pltxtLen)
{
	return GCI_OK;
}

GciResult_t gci_rng_gen(int rdmNb, uint8_t* rdmBuf)
{
	return GCI_OK;
}


GciResult_t gci_rng_seed(const uint8_t* sdBuf, size_t sdLen)
{
	return GCI_OK;
}


GciResult_t gci_dh_new_ctx(const GciDhConfig_t* dhConfig, GciCtxId_t* ctxID)
{
	return GCI_OK;
}

GciResult_t gci_dh_gen_key(GciCtxId_t ctxID, GciKeyId_t* pubKeyID)
{
	return GCI_OK;
}


GciResult_t gci_dh_calc_sharedSecret(GciCtxId_t ctxID, GciKeyId_t pubKeyID, GciKeyId_t* secretKeyID)
{
	return GCI_OK;
}


GciResult_t gci_key_put(const GciKey_t* key, GciKeyId_t* keyID)
{
	return GCI_OK;
}

GciResult_t gci_key_get(GciKeyId_t keyID, GciKey_t* key)
{
	return GCI_OK;
}


GciResult_t gci_key_delete(GciKeyId_t keyID)
{
	return GCI_OK;
}
