/*****************************************************************************/
/*                                                                           */
/*  MODULE NAME: ssl_diag.c                                                 */
/*                                                                           */
/*  FUNCTIONS:                                                               */
/*                                                                           */
/*                                                                           */
/*                                                                           */
/*  DESCRIPTION:                                                             */
/*   This module implements functions which print diagnostics or debug       */
/*   messages.                                                               */
/*                                                                           */
/*                                                                           */
/*                                                                           */
/*  CAUTIONS:                                                                */
/*                                                                           */
/*                                                                           */
/*                                                                           */
/*  LANGUAGE:        ANSI C                 COMPILER:                        */
/*  TARGET SYSTEM:                                                           */
/*                                                                           */
/*****************************************************************************/
/*                                                                           */
/*  MODIFICATION HISTORY: (Optional for DSEE files)                          */
/*                                                                           */
/*  Date        Person        Change                                         */
/*  ====        ======        ======                                         */
/*  28.03.03     WAM           Initial version                               */
/*                                                                           */
/*                                                                           */
/*  \version  $Version$                                                      */
/*                                                                           */
/*****************************************************************************/

#include "ssl_diag.h"
#include "ssl_target.h"
#include "ssl_oid.h"
#include "ssl_certHelper.h"


/*** Defines ****************************************************************/

#define BOOL_TO_STRING(x) ((x)?"TRUE":"FALSE")

#define	LOGGER_ENABLE		DBG_SSL_DIAG
#include "logger.h"

/*** Global Variables *******************************************************/

/*** Local Variables ********************************************************/

/*! Transforms "a" to a case of a switch-case structure that returns its name */
#define SSL_DIAG_NAME2CASE(a)    case a: return #a

/*** Forward declarations ***************************************************/


/*** Local Prototypes ********************************************************/
static char* loc_getClientAuthBehav(e_sslAuthLevel_t beh);
static char* loc_getRecType(e_sslRecType_t type);
static char* loc_getSrvAction(e_sslPendAct_t evt);
static char* loc_getSocState(e_sslSocState_t state);

/*** Local Functions ********************************************************/

static char* loc_getClientAuthBehav(e_sslAuthLevel_t beh) {
  switch(beh) {
    SSL_DIAG_NAME2CASE(E_SSL_NO_AUTH);
    SSL_DIAG_NAME2CASE(E_SSL_SHOULD_AUTH);
    SSL_DIAG_NAME2CASE(E_SSL_MUST_AUTH);
    SSL_DIAG_NAME2CASE(E_SSL_MUST_VERF_SRVCERT);
    SSL_DIAG_NAME2CASE(E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_NO_AUTH);
    SSL_DIAG_NAME2CASE(E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_SHOULD_AUTH);
    SSL_DIAG_NAME2CASE(E_SSL_MUST_VERF_SRVCERT_AND_E_SSL_MUST_AUTH);
    default: return "Invalid Behavior";
  }
}

static char* loc_getRecType(e_sslRecType_t type) {
  switch(type) {
      SSL_DIAG_NAME2CASE(E_SSL_RT_CHANGE_CIPSPEC);
      SSL_DIAG_NAME2CASE(E_SSL_RT_ALERT);
      SSL_DIAG_NAME2CASE(E_SSL_RT_HANDSHAKE);
      SSL_DIAG_NAME2CASE(E_SSL_RT_APPDATA);
      default: return "Invalid Record Type";
  }
}

static char* loc_getSrvAction(e_sslPendAct_t evt) {
  switch(evt) {

    case E_PENDACT_GEN_START: return "E_PENDACT_GEN_START";
    case E_PENDACT_GEN_WAIT_EVENT: return "E_PENDACT_GEN_WAIT_EVENT";
    case E_PENDACT_SRV_START: return "E_PENDACT_SRV_START";
    case E_PENDACT_SRV_RECORD: return "E_PENDACT_SRV_RECORD";
    case E_PENDACT_SRV_APPRESP: return "E_PENDACT_SRV_APPRESP";
    case E_PENDACT_SRV_PKCS1_DECRYPT: return "E_PENDACT_SRV_PKCS1_DECRYPT";
    case E_PENDACT_SRV_PKCS1_VERIFY: return "E_PENDACT_SRV_PKCS1_VERIFY";
    case E_PENDACT_SRV_CERTVERIFY: return "E_PENDACT_SRV_CERTVERIFY";
    case E_PENDACT_SRV_CLICERTCHAIN: return "E_PENDACT_SRV_CLICERTCHAIN";
    case E_PENDACT_SRV_WARNING: return "E_PENDACT_SRV_WARNING";
    case E_PENDACT_SRV_FATAL_ERROR: return "E_PENDACT_SRV_FATAL_ERROR";
    case E_PENDACT_SRV_SCACHE: return "E_PENDACT_SRV_SCACHE";
    case E_PENDACT_CLI_PKCS1_ENCRYPT: return "E_PENDACT_CLI_PKCS1_ENCRYPT";
    case E_PENDACT_CLI_PKCS1_SIGN: return "E_PENDACT_CLI_PKCS1_SIGN";
    case E_PENDACT_COM_START: return "E_PENDACT_COM_START";
    case E_PENDACT_COM_CIPHER_LENERROR: return "E_PENDACT_COM_CIPHER_LENERROR";
    case E_PENDACT_COM_CIPHER_TX: return "E_PENDACT_COM_CIPHER_TX";
    case E_PENDACT_COM_CIPHER_TXCLOSE: return "E_PENDACT_COM_CIPHER_TXCLOSE";
    case E_PENDACT_COM_CIPHER_CLOSE: return "E_PENDACT_COM_CIPHER_CLOSE";
    case E_PENDACT_COM_CIPHER_RX: return "E_PENDACT_COM_CIPHER_RX";
    case E_PENDACT_COM_PLAIN_TX: return "E_PENDACT_COM_PLAIN_TX";
    case E_PENDACT_APP_START: return "E_PENDACT_APP_START";
    case E_PENDACT_APP_REQUEST: return "E_PENDACT_APP_REQUEST";
    case E_PENDACT_APP_WRITE: return "E_PENDACT_APP_WRITE";
    case E_PENDACT_SCACHE_START: return "E_PENDACT_SCACHE_START";
    case E_PENDACT_SCACHE_GET: return "E_PENDACT_SCACHE_GET";
    case E_PENDACT_SCACHE_INS: return "E_PENDACT_SCACHE_INS";
    case E_PENDACT_SCACHE_RM: return "E_PENDACT_SCACHE_RM";
    case E_PENDACT_SCACHE_FIND: return "E_PENDACT_SCACHE_FIND";
    case E_PENDACT_ASYM_START: return "E_PENDACT_ASYM_START";
    case E_PENDACT_ASYM_PKCS1_DECRYPT: return "E_PENDACT_ASYM_PKCS1_DECRYPT";
    case E_PENDACT_ASYM_PKCS1_VERIFY: return "E_PENDACT_ASYM_PKCS1_VERIFY";
    case E_PENDACT_ASYM_CERTVERIFY: return "E_PENDACT_ASYM_CERTVERIFY";
    case E_PENDACT_ASYM_CLICERTCHAIN: return "E_PENDACT_ASYM_CLICERTCHAIN";
    case E_PENDACT_ASYM_PKCS1_ENCRYPT: return "E_PENDACT_ASYM_PKCS1_ENCRYPT";
    case E_PENDACT_ASYM_PKCS1_SIGN: return "E_PENDACT_ASYM_PKCS1_SIGN";
    case E_PENDACT_EXTERNAL_ACTION: return "E_PENDACT_EXTERNAL_ACTION";
    case E_PENDACT_INTERNAL_START: return "E_PENDACT_INTERNAL_START";
    case E_PENDACT_INCOMING_REC: return "E_PENDACT_INCOMING_REC";
    case E_PENDACT_APPRESP: return "E_PENDACT_APPRESP or E_PENDACT_PKCS1_DECRYPT...";
    /*case E_PENDACT_PKCS1_DECRYPT: return "E_PENDACT_PKCS1_DECRYPT";*/
    case E_PENDACT_PKCS1_VERIFY: return "E_PENDACT_PKCS1_VERIFY";
    case E_PENDACT_CERTVERIFY: return "E_PENDACT_CERTVERIFY";
    case E_PENDACT_SEND_WARNING: return "E_PENDACT_SEND_WARNING";
    case E_PENDACT_SEND_FATAL_ERROR: return "E_PENDACT_SEND_FATAL_ERROR";
    case E_PENDACT_UNKNOWN: return "E_PENDACT_UNKNOWN";
    case E_PENDACT_HANDSHAKE: return "E_PENDACT_HANDSHAKE";
    case E_PENDACT_DISPATCH_MSG: return "E_PENDACT_DISPATCH_MSG";
    case E_PENDACT_ERROR_MAC_FAIL: return "E_PENDACT_ERROR_MAC_FAIL";
    case E_PENDACT_RESPREC: return "E_PENDACT_RESPREC";
    case E_PENDACT_MSG_ASM: return "E_PENDACT_MSG_ASM";
    case E_PENDACT_MAC_ENCRYPT_REC: return "E_PENDACT_MAC_ENCRYPT_REC";
    case E_PENDACT_PROTORESPGEN: return "E_PENDACT_PROTORESPGEN";
    case E_PENDACT_DECRYPT_MAC_CHECK: return "E_PENDACT_DECRYPT_MAC_CHECK";
    case E_PENDACT_PROTOHANDLER: return "E_PENDACT_PROTOHANDLER";
    case E_PENDACT_V2UPWARDHANDLER: return "E_PENDACT_V2UPWARDHANDLER";
    case E_PENDACT_PROTOERR: return "E_PENDACT_PROTOERR";
    case E_PENDACT_MAC_ENCRYPT_HANDSHAKE: return "E_PENDACT_MAC_ENCRYPT_HANDSHAKE";
    case E_PENDACT_PKCS1_ENCRYPT: return "E_PENDACT_PKCS1_ENCRYPT";
    case E_PENDACT_END: return "E_PENDACT_END";
    default: return "Invalid e_sslPendAct_t type";
  }
}

static char* loc_getSocState(e_sslSocState_t state) {
  switch(state) {
    case E_SSL_SOCKET_UNUSED: return "Socket unused";
    case E_SSL_SOCKET_IDLE: return "Socket idle";
    case E_SSL_SOCKET_RXBUFF: return "Get Ciphertext from network";
    case E_SSL_SOCKET_READOUT: return "Get Plaintext from buffer";
    case E_SSL_SOCKET_TXBUFF: return "Put Ciphertext to network";
    case E_SSL_SOCKET_READIN: return "Put Plaintext to buffer";
    default: return "Invalid socketstate";
  }
}

/*** Global Functions *******************************************************/

char* sslDiag_getAssembly(uint8_t assem) {
  switch(assem) {
    case E_SSL_ASM_START: return "E_SSL_ASM_START";
    case E_SSL_ASM_STEP1: return "E_SSL_ASM_STEP1";
    case E_SSL_ASM_STEP2: return "E_SSL_ASM_STEP2";
    case E_SSL_ASM_STEP3: return "E_SSL_ASM_STEP3";
    case E_SSL_ASM_STEP4: return "E_SSL_ASM_STEP4";
    case E_SSL_ASM_FINISH: return "E_SSL_ASM_FINISH";
    default: return "Invalid Assembly state";
  }
}

char* sslDiag_getSMState(e_sslSmStatus_t state) {
  switch(state) {
    case E_SSL_SM_WAIT_INIT: return "E_SSL_SM_WAIT_INIT";
    case E_SSL_SM_WAIT_CLIENT_HELLO: return "E_SSL_SM_WAIT_CLIENT_HELLO";
    case E_SSL_SM_WAIT_CLIENT_CERTIFICATE: return "E_SSL_SM_WAIT_CLIENT_CERTIFICATE";
    case E_SSL_SM_WAIT_CLIENT_KEYEXCHANGE: return "E_SSL_SM_WAIT_CLIENT_KEYEXCHANGE";
    case E_SSL_SM_WAIT_CLIENT_CERT_VERIFY: return "E_SSL_SM_WAIT_CLIENT_CERT_VERIFY";
    case E_SSL_SM_WAIT_CHANGE_CIPHERSPEC: return "E_SSL_SM_WAIT_CHANGE_CIPHERSPEC";
    case E_SSL_SM_WAIT_CLIENT_FINISH: return "E_SSL_SM_WAIT_CLIENT_FINISH";
    case E_SSL_SM_SEND_SERVER_HELLO_FINISH: return "E_SSL_SM_SEND_SERVER_HELLO_FINISH";
    case E_SSL_SM_SEND_SERVER_HELLO: return "E_SSL_SM_SEND_SERVER_HELLO";
    case E_SSL_SM_SEND_SERVER_FINISH: return "E_SSL_SM_SEND_SERVER_FINISH";
    case E_SSL_SM_SEND_WARN_ALERT: return "E_SSL_SM_SEND_WARN_ALERT";
    case E_SSL_SM_SEND_FATAL_ALERT: return "E_SSL_SM_SEND_FATAL_ALERT";
    case E_SSL_SM_SEND_CLIENT_HELLO: return "E_SSL_SM_SEND_CLIENT_HELLO";
    case E_SSL_SM_SEND_CLIENT_FINISH: return "E_SSL_SM_SEND_CLIENT_FINISH";
    case E_SSL_SM_WAIT_SERVER_HELLO: return "E_SSL_SM_WAIT_SERVER_HELLO";
    case E_SSL_SM_WAIT_CERT: return "E_SSL_SM_WAIT_CERT";
    case E_SSL_SM_WAIT_SERVER_KEYEXCHANGE: return "E_SSL_SM_WAIT_SERVER_KEYEXCHANGE";
    case E_SSL_SM_WAIT_CERT_REQUEST: return "E_SSL_SM_WAIT_CERT_REQUEST";
    case E_SSL_SM_WAIT_SERVER_HELLO_DONE: return "E_SSL_SM_WAIT_SERVER_HELLO_DONE";
    case E_SSL_SM_WAIT_SERVER_FINISH: return "E_SSL_SM_WAIT_SERVER_FINISH";
    case E_SSL_SM_SEND_SHUTDOWN: return "E_SSL_SM_SEND_SHUTDOWN";
    case E_SSL_SM_SHUTDOWN_SENT: return "E_SSL_SM_SHUTDOWN_SENT";
    case E_SSL_SM_SHUTDOWN_COMPLETE: return "E_SSL_SM_SHUTDOWN_COMPLETE";
    case E_SSL_SM_APPDATA_EXCHANGE: return "E_SSL_SM_APPDATA_EXCHANGE";
    default: return "Invalid state of internal StateMachine";
  }
}

char* sslDiag_getError(s_sslCtx_t* ctx) {
  switch(ctx->e_lastError) {
    case E_SSL_NO_ERROR: return "No error occured";
    case E_SSL_NO_ERROR_SHDOWN: return "No error shutdown completed";
    case E_SSL_ERROR_GENERAL: return "E_SSL_ERROR_GENERAL";
    case E_SSL_ERROR_BUFFEROFLOW: return "E_SSL_ERROR_BUFFEROFLOW";
    case E_SSL_ERROR_WOULDBLOCK: return "E_SSL_ERROR_WOULDBLOCK";
    case E_SSL_ERROR_DECRYT: return "E_SSL_ERROR_DECRYT";
    case E_SSL_ERROR_ENCRYPT: return "E_SSL_ERROR_ENCRYPT";
    case E_SSL_ERROR_BADMAC: return "E_SSL_ERROR_BADMAC";
    case E_SSL_ERROR_VERSION: return "E_SSL_ERROR_VERSION";
    case E_SSL_ERROR_SOCKET: return "E_SSL_ERROR_SOCKET";
    case E_SSL_ERROR_SOCSTATE: return "E_SSL_ERROR_SOCSTATE";
    case E_SSL_ERROR_SM : return "E_SSL_ERROR_SM ";
    case E_SSL_ERROR_PROTO: return "E_SSL_ERROR_PROTO";
    case E_SSL_ERROR_CRYPTO: return "E_SSL_ERROR_CRYPTO";
    case E_SSL_ERROR_LENGTH: return "E_SSL_ERROR_LENGTH";
    default: return "Invalid Errorcode";
  }
}

char* sslDiag_getCertHandErr (int err) {
  switch(err) {
    case E_SSL_CERT_OK: return "E_SSL_CERT_OK";
    case E_SSL_CERT_ERR: return "E_SSL_CERT_ERR";
    case E_SSL_CERT_ERR_INVALID_HASH: return "E_SSL_CERT_ERR_INVALID_HASH";
    case E_SSL_CERT_ERR_PROCESS_FAILED: return "E_SSL_CERT_ERR_PROCESS_FAILED";
    case E_SSL_CERT_ERR_VERIFICATION_FAILED: return "E_SSL_CERT_ERR_VERIFICATION_FAILED";
    case E_SSL_CERT_ERR_CA_NOT_KNOWN: return "E_SSL_CERT_ERR_CA_NOT_KNOWN";
    case E_SSL_CERT_ERR_EXT_BASIC_CONSTRAINTS: return "E_SSL_CERT_ERR_EXT_BASIC_CONSTRAINTS";
    case E_SSL_CERT_ERR_EXT_BC_CA_MISSING: return "E_SSL_CERT_ERR_EXT_BC_CA_MISSING";
    case E_SSL_CERT_ERR_EXT_BC_PATHLEN_ERR: return "E_SSL_CERT_ERR_EXT_BC_PATHLEN_ERR";
    case E_SSL_CERT_ERR_EXT_KEYUSAGE: return "E_SSL_CERT_ERR_EXT_KEYUSAGE";
    case E_SSL_CERT_ERR_STRUCT_FAIL: return "E_SSL_CERT_ERR_STRUCT_FAIL";
    case E_SSL_CERT_ERR_NO_OBJECT: return "E_SSL_CERT_ERR_NO_OBJECT";
    case E_SSL_CERT_MORE_ELEMENTS_AVAILABLE: return "E_SSL_CERT_MORE_ELEMENTS_AVAILABLE";
    default: return "Invalid Errorcode";
  }
}

char* sslDiag_getCertError (int err) {
  switch(err) {
    SSL_DIAG_NAME2CASE(E_SSL_CERT_OK);
    SSL_DIAG_NAME2CASE(E_SSL_CERT_BUFFER_NOT_SET);
    SSL_DIAG_NAME2CASE(E_SSL_CERT_ERR);
    SSL_DIAG_NAME2CASE(E_SSL_CERT_ERR_DECODING_FAILED);
    SSL_DIAG_NAME2CASE(E_SSL_CERT_ERR_NO_CA);
    SSL_DIAG_NAME2CASE(E_SSL_CERT_ERR_PATHLENCONSTRAINT);
    SSL_DIAG_NAME2CASE(E_SSL_CERT_ERR_BASICCONSTRAINTS);
    SSL_DIAG_NAME2CASE(E_SSL_CERT_ERR_NO_ROOT_AVAILABLE);
    SSL_DIAG_NAME2CASE(E_SSL_CERT_ERR_SELF_SIGNED);
    SSL_DIAG_NAME2CASE(E_SSL_CERT_ERR_PUBLIC_KEY);
    SSL_DIAG_NAME2CASE(E_SSL_CERT_ERR_VERIF_FAILED);
    SSL_DIAG_NAME2CASE(E_SSL_CERT_ERR_SMALL_BUFFER);
    default: return "Invalid Errorcode";
  }
}

char* sslDiag_getCipherSuite(e_sslCipSpec_t cs) {
  switch(cs) {
      SSL_DIAG_NAME2CASE(TLS_NULL_WITH_NULL_NULL);
      SSL_DIAG_NAME2CASE(TLS_RSA_WITH_RC4_128_MD5);
      SSL_DIAG_NAME2CASE(TLS_RSA_WITH_RC4_128_SHA);
      SSL_DIAG_NAME2CASE(TLS_RSA_WITH_3DES_EDE_CBC_SHA);
      SSL_DIAG_NAME2CASE(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
      SSL_DIAG_NAME2CASE(TLS_RSA_WITH_AES_128_CBC_SHA);
      SSL_DIAG_NAME2CASE(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
      SSL_DIAG_NAME2CASE(TLS_RSA_WITH_AES_256_CBC_SHA);
      SSL_DIAG_NAME2CASE(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
      SSL_DIAG_NAME2CASE(TLS_RSA_WITH_AES_128_CBC_SHA256);
      SSL_DIAG_NAME2CASE(TLS_RSA_WITH_AES_256_CBC_SHA256);
      SSL_DIAG_NAME2CASE(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
      SSL_DIAG_NAME2CASE(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);

      //begin vpy
      SSL_DIAG_NAME2CASE(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
      SSL_DIAG_NAME2CASE(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
      SSL_DIAG_NAME2CASE(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
      SSL_DIAG_NAME2CASE(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
      SSL_DIAG_NAME2CASE(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
      SSL_DIAG_NAME2CASE(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
      //end vpy

      SSL_DIAG_NAME2CASE(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
      SSL_DIAG_NAME2CASE(TLS_UNDEFINED);
      default: return "Invalid Ciphersuite";
  }
}

char* sslDiag_getAlert(e_sslAlertType_t alert) {
  switch(alert) {
    case E_SSL_ALERT_CLOSE_NOTIFY: return "E_SSL_ALERT_CLOSE_NOTIFY";
    case E_SSL_ALERT_UNEXP_MSG: return "E_SSL_ALERT_UNEXP_MSG";
    case E_SSL_ALERT_BAD_RECORD_MAC: return "E_SSL_ALERT_BAD_RECORD_MAC";
    case E_SSL_ALERT_DECR_FAILED: return "E_SSL_ALERT_DECR_FAILED";
    case E_SSL_ALERT_REC_OFLOW: return "E_SSL_ALERT_REC_OFLOW";
    case E_SSL_ALERT_DECOMPR_FAIL: return "E_SSL_ALERT_DECOMPR_FAIL";
    case E_SSL_ALERT_HANDSH_FAIL: return "E_SSL_ALERT_HANDSH_FAIL";
    case E_SSL_ALERT_NO_CERT: return "E_SSL_ALERT_NO_CERT";
    case E_SSL_ALERT_BAD_CERT: return "E_SSL_ALERT_BAD_CERT";
    case E_SSL_ALERT_UNSUP_CERT: return "E_SSL_ALERT_UNSUP_CERT";
    case E_SSL_ALERT_CERT_REVOKED: return "E_SSL_ALERT_CERT_REVOKED";
    case E_SSL_ALERT_CERT_EXPIRED: return "E_SSL_ALERT_CERT_EXPIRED";
    case E_SSL_ALERT_CERT_UNKNOWN: return "E_SSL_ALERT_CERT_UNKNOWN";
    case E_SSL_ALERT_ILLEGAL_PARAM: return "E_SSL_ALERT_ILLEGAL_PARAM";
    case E_SSL_ALERT_UNKNOWN_CA: return "E_SSL_ALERT_UNKNOWN_CA";
    case E_SSL_ALERT_ACCESS_DENIED: return "E_SSL_ALERT_ACCESS_DENIED";
    case E_SSL_ALERT_DECODE_ERR: return "E_SSL_ALERT_DECODE_ERR";
    case E_SSL_ALERT_DECR_ERR: return "E_SSL_ALERT_DECR_ERR";
    case E_SSL_ALERT_EXPORT_RESTR: return "E_SSL_ALERT_EXPORT_RESTR";
    case E_SSL_ALERT_PROTO_VER: return "E_SSL_ALERT_PROTO_VER";
    case E_SSL_ALERT_PUNSUFF_SEC: return "E_SSL_ALERT_PUNSUFF_SEC";
    case E_SSL_ALERT_INTERNAL_ERR: return "E_SSL_ALERT_INTERNAL_ERR";
    case E_SSL_ALERT_USER_CANCELED: return "E_SSL_ALERT_USER_CANCELED";
    case E_SSL_ALERT_NO_RENEG: return "E_SSL_ALERT_NO_RENEG";
    default: return "Invalid Alert";
  }
}

char* sslDiag_getVersion(e_sslVer_t v) {
  switch(v) {
    case E_SSL_3_0: return "SSL 3.0";
    case E_TLS_1_0: return "TLS 1.0";
    case E_TLS_1_1: return "TLS 1.1";
    case E_TLS_1_2: return "TLS 1.2";
    case E_VER_DCARE: return "E_VER_DCARE";
    default: return "Invalid version";
  }
}

char* sslDiag_getSigAlg(int id)
{
  switch(id)
  {
    case SSL_OID_MD5_WITH_RSA_ENC: return "SSL_OID_MD5_WITH_RSA_ENC";
    case SSL_OID_SHA1_WITH_RSA_ENC: return "SSL_OID_SHA1_WITH_RSA_ENC";
    case SSL_OID_SHA256_WITH_RSA_ENC: return "SSL_OID_SHA256_WITH_RSA_ENC";
    case SSL_OID_SHA384_WITH_RSA_ENC: return "SSL_OID_SHA384_WITH_RSA_ENC";
    case SSL_OID_SHA512_WITH_RSA_ENC: return "SSL_OID_SHA512_WITH_RSA_ENC";
    case SSL_OID_SHA256_WITH_ECDSA_ENC: return "SSL_OID_SHA256_WITH_ECDSA_ENC"; //vpy
    default: return "Unknown Signature Algorithm";
  }
}

char* sslDiag_getExtension (e_tlsExt_t ext)
{
    switch (ext) {
        SSL_DIAG_NAME2CASE(TLS_EXTENSION_SERVER_NAME);
        SSL_DIAG_NAME2CASE(TLS_EXTENSION_MAX_FRAGMENT_LENGTH);
        SSL_DIAG_NAME2CASE(TLS_EXTENSION_CLIENT_CERTIFICATE_URL);
        SSL_DIAG_NAME2CASE(TLS_EXTENSION_TRUSTED_CA_KEYS);
        SSL_DIAG_NAME2CASE(TLS_EXTENSION_TRUNCATED_HMAC);
        SSL_DIAG_NAME2CASE(TLS_EXTENSION_STATUS_REQUEST);
        SSL_DIAG_NAME2CASE(TLS_EXTENSION_ELLIPTIC_CURVES);
        SSL_DIAG_NAME2CASE(TLS_EXTENSION_EC_POINT_FORMATS);
        SSL_DIAG_NAME2CASE(TLS_EXTENSION_SIGNATURE_ALGORITHMS);
        SSL_DIAG_NAME2CASE(TLS_EXTENSION_SESSIONTICKET_TLS);
        SSL_DIAG_NAME2CASE(TLS_EXTENSION_RENEGOTIATION_INFO);
        SSL_DIAG_NAME2CASE(TLS_EXTENSION_UNDEFINED);
        default: return "Unknown Extension";
    }
}

char* sslDiag_getHashAlg (uint8_t hash)
{
    switch (hash) {
        SSL_DIAG_NAME2CASE(E_SSL_HASH_NONE);
        SSL_DIAG_NAME2CASE(E_SSL_HASH_MD5);
        SSL_DIAG_NAME2CASE(E_SSL_HASH_SHA1);
        SSL_DIAG_NAME2CASE(E_SSL_HASH_SHA256);
        default: return NULL;
    }
}

char* sslDiag_getSignAlg (uint8_t sign)
{
    switch (sign) {
        SSL_DIAG_NAME2CASE(E_SSL_SIGN_ANONY);
        SSL_DIAG_NAME2CASE(E_SSL_SIGN_RSA);
        SSL_DIAG_NAME2CASE(E_SSL_SIGN_DSA);
        SSL_DIAG_NAME2CASE(E_SSL_SIGN_ECDSA);
        default: return NULL;
    }
}

void sslDiag_printHex(uint8_t *pcData, uint32_t iDataLen)
{
    sslDiag_printHexData(" ", pcData, iDataLen);
}

void sslDiag_printHexData(rpcw_str_t descriptor, uint8_t *pcData, uint32_t iDataLen)
{
    unsigned int i;
    int iMaxLen;
    int iTail;

    uint8_t *pc;

    assert(pcData != NULL);

    printf("%s - [%d bytes]\n", descriptor, iDataLen);

    if (!iDataLen)
        return;

    iMaxLen = ((iDataLen - 1) / 16 + 1) * 16 + 1;

    pc = pcData;

    iTail = 0;
    for (i = 0; i < iMaxLen; i++)
    {
        /* Handling of content in ASCII display */
        if ((i & 0x0F) == 0 && i != 0)
        {
            /* Separator between hex and ASCII part of line */
            printf(" | ");

            while (pc < pcData)
            {
                /* Only printable chars to be displayed as ASCII char */
                if (*pc < 128 && *pc >= 32)
                {
                    printf("%c", *pc++);
                }
                else
                {
                    printf(".");
                    pc++;
                }
            }

            /* Add blanks for each fillbyte */
            while (iTail > 0)
            {
                printf(" ");
                iTail--;
            }

            printf(" |\n");
        }

        /* Print out the content in hex display */
        if (i < iDataLen)
        {
            printf("%02x ", *pcData++);
        }
        else
        {
            /* Count number of Fillbytes */
            printf("   ");
            iTail++;
        }
    }
    printf("\n");

}

void sslDiag_printGenericString(s_sslGenStr_t * ps_str, rpcw_str_t p_name)
{
    uint8_t ac_string[DBG_SSL_MAX_DEBUG_STRING_LEN];
    assert(ps_str != NULL);
    assert(ps_str->pc_data != NULL);

    if(SSL_DER_ASN1_IS_STRPRINT(ps_str->iStringType))
    {
        int len2cpy = ((ps_str->cwt_len < DBG_SSL_MAX_DEBUG_STRING_LEN) ? ps_str->cwt_len : (DBG_SSL_MAX_DEBUG_STRING_LEN - 1));

        CW_MEMSET(ac_string, 0, DBG_SSL_MAX_DEBUG_STRING_LEN);
        CW_MEMCOPY(ac_string, ps_str->pc_data, len2cpy);

        if(len2cpy < ps_str->cwt_len)
            printf("(cropped)");

        printf(" %s: %s\n", p_name, ac_string);

        if(CW_STRLEN((char *)ps_str->pc_data) < ps_str->cwt_len)
            printf(" rogue %s occured! string length not equal to ASN.1 length", p_name);
    }
    else
    {
        sslDiag_printHexData(p_name, ps_str->pc_data, ps_str->cwt_len);
    }
}

void sslDiag_printSessHsElem(s_sslHsElem_t* elmt, int details)
{
    if(details) {
        printf("\r\n--------------------------------------------------");
        printf("\r\n\tContent of Handshake Element @ %p", elmt);
        printf("\r\n--------------------------------------------------");
        printf("\r\nSession ID");
        sslDiag_printHex(elmt->s_sessElem.ac_id, SESSID_SIZE);
        printf("\r\nMaster Secret");
        sslDiag_printHex(elmt->s_sessElem.ac_msSec, MSSEC_SIZE);
        printf("\r\nServer Random");
        sslDiag_printHex(elmt->ac_srvRand, SRV_RANDSIZE);
        printf("\r\nClient Random");
        sslDiag_printHex(elmt->ac_cliRand, CLI_RANDSIZE);
        if(details > 1) {

        }
    }
}


void sslDiag_printSessKeys(s_sslSecParams_t* keys, int details)
{
    if(details) {
        printf("\r\n--------------------------------------------------");
        printf("\r\n\tContent of Session Keys @ %p", keys);
        printf("\r\n--------------------------------------------------");
        printf("\r\nBlocklen if a BlockCipher is used: %d", keys->c_blockLen);
        printf("\r\nServer MAC secret");
        sslDiag_printHex(keys->ac_srvSecret, 20);
        printf("\r\nClient MAC secret");
        sslDiag_printHex(keys->ac_cliSecret, 20);
        if(details > 1) {

        }
    }
}

void sslDiag_printInternals(s_sslGut_t* internal, int details) {
  if(details) {
    int i = 0;
    printf("\r\n--------------------------------------------------");
    printf("\r\n\tContent of SSL Internals @ %p", internal);
    printf("\r\n--------------------------------------------------");
    printf("\r\nSM Status:      %s", sslDiag_getSMState(internal->e_smState));
    printf("\r\nAssembly State: %s", sslDiag_getAssembly(internal->e_asmCtrl));
    printf("\r\nRecord Type:    %s", loc_getRecType(internal->e_recordType));
    printf("\r\nAlert Type:     %s", sslDiag_getAlert(internal->e_alertType));
    printf("\r\nClnt Seq Num:   %d", ntohl(*((uint32_t*)&(internal->ac_cliSeqNum[4]))));
    printf("\r\nSrvr Seq Num:   %d", ntohl(*((uint32_t*)&(internal->ac_srvrSeqNum[4]))));
    printf("\r\n--------------------------------------------------");
    printf("\r\n\t\tCiphersuites");
    printf("\r\n--------------------------------------------------");
    printf("\r\nReceive:        %s", sslDiag_getCipherSuite(internal->e_rxCipSpec));
    printf("\r\nTransmit:       %s", sslDiag_getCipherSuite(internal->e_txCipSpec));
    for(;i<SSL_CIPSPEC_COUNT;i++)
    {
        printf("\r\nPossible %i:     %s", (i+1), sslDiag_getCipherSuite(internal->ae_cipSpecs[i]));
    }
  }
}

void sslDiag_printSsl(s_sslCtx_t* ctx, int details)
{
    printf("\r\n--------------------------------------------------");
    printf("\r\n\tContent of SSL Context @ %p", ctx);
    printf("\r\n--------------------------------------------------");
    printf("\r\nSocketstate:     %s", loc_getSocState(ctx->e_socState));
    printf("\r\nTCP/IP socket:   %i (255 means unused)", ctx->i_socNum);
    printf("\r\nIs resumable:    %s", BOOL_TO_STRING(ctx->c_isResumed));
    printf("\r\nIs client:       %s", BOOL_TO_STRING(ctx->b_isCli));
    printf("\r\nAuth. Behaviour: %s %i", loc_getClientAuthBehav(ctx->e_authLvl), ctx->e_authLvl);
    printf("\r\nHandshake CTX:   %i", ctx->l_hsCtx);
    printf("\r\nCurrent event:   %s %i", loc_getSrvAction(ctx->e_event), ctx->e_event);
    printf("\r\nCurrent action:  %s %i", loc_getSrvAction(ctx->e_nextAction), ctx->e_nextAction);
    printf("\r\nLast error:      %s %i", sslDiag_getError(ctx), ctx->e_lastError);
    printf("\r\n--------------------------------------------------");
    printf("\r\n\tBuffer details");
    printf("\r\n--------------------------------------------------");
    printf("\r\nBufferlength:   %i", ctx->l_buffLen);
    printf("\r\nWrite Offset:   %i", ctx->l_writeOff);
    printf("\r\nRead Offset:    %i", ctx->l_readOff);

    sslDiag_printInternals(&(ctx->s_sslGut), details);
    sslDiag_printSessKeys(&(ctx->s_secParams), details);
    sslDiag_printSessHsElem(ctx->ps_hsElem, details);

    printf("\r\n--------------------------------------------------");
    printf("\r\n");
    /* printf("\r\n"); */
    /* case : return ""; */
}
