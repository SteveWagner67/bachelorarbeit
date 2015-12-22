#ifndef _LOGGER_H_
#define _LOGGER_H_

#include <stdlib.h>
#include <stdio.h>
#include "ssl_diag.h"

#include "timestamps.h"
#define TIME_STAMP(x)			timeStamp(x)

#define TS_LIB_INIT_BEGIN              0x0
#define TS_LIB_INIT_END                0x1
#define TS_SENT_HS_CERTIFICATE         0xb3
#define TS_PRF_BEGIN                   0x10
#define TS_PRF_END                     0x11
#define TS_PMS_DECRYPT_BEGIN           0x14
#define TS_PMS_DECRYPT_END             0x15
#define TS_PMS_ENCRYPT_BEGIN           0x16
#define TS_PMS_ENCRYPT_END             0x17
#define TS_DHE_SIGN_BEGIN              0x20
#define TS_DHE_SIGN_HASHED             0x21
#define TS_DHE_SIGN_END                0x22
#define TS_RECEIVED_HS_CERT            0xa3
#define TS_DHE_CALC_SHARED_SEC_BEGIN   0x24
#define TS_DHE_CALC_SHARED_SEC_END     0x25
#define TS_ECDHE_CALC_SHARED_SEC_BEGIN 0x26
#define TS_ECDHE_CALC_SHARED_SEC_END   0x27
#define TS_RECEIVED_HS_SRV_HELLO_DONE  0xa6
#define TS_RECEIVED_HS_CLI_KEY_EX      0xa7
#define TS_RECEIVED_HS_CERT_VERIFY     0xa8
#define TS_RECEIVED_HS_FINISH          0xa9
#define TS_HASH_INIT_BEGIN             0x2a
#define TS_HASH_INIT_END               0x2b
#define TS_HASH_UPDATE_BEGIN           0x2c
#define TS_HASH_UPDATE_END             0x2d
#define TS_RECEIVED_CCS                0xae
#define TS_RECEIVED_ALERT              0xaf
#define TS_COMP_KEY_BEGIN              0x30
#define TS_COMP_KEY_END                0x31
#define TS_COMP_HASH_BEGIN             0x32
#define TS_COMP_HASH_END               0x33
#define TS_SENT_HS_SRV_KEY_EX          0xb4
#define TS_SENT_HS_CERT_REQ            0xb5
#define TS_SENT_HS_CLI_KEY_EX          0xb6
#define TS_SENT_HS_CERT_VERIFY         0xb7
#define TS_SENT_HS_FINISH              0xb8
#define TS_CBC_DECRYPT_BEGIN           0x58
#define TS_SENT_CCS                    0xbe
#define TS_CRT_VERF_SIGN_BEGIN         0x40
#define TS_CRT_VERF_SIGN_END           0x41
#define TS_RECEIVED_HS_CLIENT_HELLO    0xa1
#define TS_SENT_HS_SERVER_HELLO        0xb1
#define TS_RECEIVED_HS_HELLO_REQ       0xa0
#define TS_RECEIVED_HS_SERVER_HELLO    0xa2
#define TS_COMP_MAC_BEGIN              0x50
#define TS_COMP_MAC_END                0x51
#define TS_STREAM_ENCRYPT_BEGIN        0x52
#define TS_STREAM_ENCRYPT_END          0x53
#define TS_STREAM_DECRYPT_BEGIN        0x54
#define TS_STREAM_DECRYPT_END          0x55
#define TS_CBC_ENCRYPT_BEGIN           0x56
#define TS_CBC_ENCRYPT_END             0x57
#define TS_SENT_HS_CLIENT_HELLO        0xb0
#define TS_RECEIVED_HS_SRV_KEY_EX      0xa4
#define TS_RECEIVED_HS_CERT_REQ        0xa5
#define TS_SENT_HS_SRV_HELLO_DONE      0xb2
#define TS_CBC_DECRYPT_END             0x59
#define TS_CALIBRATION_BEGIN           0xfe
#define TS_CALIBRATION_END             0xff

#define TS_CRYPTO_INIT_BEGIN           0x80
#define TS_CRYPTO_INIT_END			   0x81
#define TS_DHE_INIT_BEGIN			   0x84
#define TS_DHE_INIT_END                0x85
#define TS_ECDHE_INIT_BEGIN			   0x86 //todo vpy: use timestamp
#define TS_ECDHE_INIT_END              0x87 //todo vpy: use timestamp
#define TS_SSLCTX_INIT_BEGIN		   0x88
#define TS_SSLCTX_INIT_END			   0x89
#define TS_SERV_CERT_PRIV_INIT_BEGIN   0x98
#define TS_SERV_CERT_PRIV_INIT_END	   0x99

#define LOG2_OK(msg, ...)    	LOGGER_OK(2,msg, ##__VA_ARGS__)
#define LOG2_ERR(msg, ...)   	LOGGER_ERR(2,msg, ##__VA_ARGS__)
#define LOG2_INFO(msg, ...)  	LOGGER_INFO(2,msg, ##__VA_ARGS__)
#define LOG2_WARN(msg, ...)  	LOGGER_WARN(2,msg, ##__VA_ARGS__)
#define LOG2_FAIL(msg, ...)  	LOGGER_FAIL(2,msg, ##__VA_ARGS__)
#define LOG2_DBG(msg, ...)   	LOGGER_DBG(2,msg, ##__VA_ARGS__)
#define	LOG2_RAW(...)			LOGGER_RAW(2, __VA_ARGS__)
#define LOG2_HEX(...)			LOGGER_HEX(2, __VA_ARGS__)

#define LOG1_OK(msg, ...)    	LOGGER_OK(1,msg, ##__VA_ARGS__)
#define LOG1_ERR(msg, ...)   	LOGGER_ERR(1,msg, ##__VA_ARGS__)
#define LOG1_INFO(msg, ...)  	LOGGER_INFO(1,msg, ##__VA_ARGS__)
#define LOG1_WARN(msg, ...)  	LOGGER_WARN(1,msg, ##__VA_ARGS__)
#define LOG1_FAIL(msg, ...)  	LOGGER_FAIL(1,msg, ##__VA_ARGS__)
#define LOG1_DBG(msg, ...)   	LOGGER_DBG(1,msg, ##__VA_ARGS__)
#define	LOG1_RAW(...)			LOGGER_RAW(1, __VA_ARGS__)
#define LOG1_HEX(...)			LOGGER_HEX(1, __VA_ARGS__)

#define LOG_OK(msg, ...)    	LOGGER_OK(0,msg, ##__VA_ARGS__)
#define LOG_ERR(msg, ...)   	LOGGER_ERR(0,msg, ##__VA_ARGS__)
#define LOG_INFO(msg, ...)  	LOGGER_INFO(0,msg, ##__VA_ARGS__)
#define LOG_WARN(msg, ...)  	LOGGER_WARN(0,msg, ##__VA_ARGS__)
#define LOG_FAIL(msg, ...)  	LOGGER_FAIL(0,msg, ##__VA_ARGS__)
#define LOG_DBG(msg, ...)   	LOGGER_DBG(0,msg, ##__VA_ARGS__)
#define	LOG_RAW(msg, ...)		LOGGER_RAW(0,msg, ##__VA_ARGS__)
#define LOG_HEX(...)            LOGGER_HEX(0, __VA_ARGS__)
#define LOG_HEX_NAME(...)       LOGGER_HEX_NAME(0, __VA_ARGS__)

#define LOGGER_OK(log_lvl, msg, ...)    	\
	do { if ((LOGGER_ENABLE) && (LOGGER_LEVEL > log_lvl)) printf("  ok | %5s (%d)| " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); }while (0)

#define LOGGER_ERR(log_lvl, msg, ...)    	\
	do { if ((LOGGER_ENABLE) && (LOGGER_LEVEL > log_lvl)) printf(" err | %5s (%d)| " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); }while (0)

#define LOGGER_INFO(log_lvl, msg, ...)    	\
	do { if ((LOGGER_ENABLE) && (LOGGER_LEVEL > log_lvl)) printf("info | %5s (%d)| " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); }while (0)

#define LOGGER_WARN(log_lvl, msg, ...)    	\
	do { if ((LOGGER_ENABLE) && (LOGGER_LEVEL > log_lvl)) printf("warn | %5s (%d)| " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); }while (0)

#define LOGGER_FAIL(log_lvl, msg, ...)    	\
	do { if ((LOGGER_ENABLE) && (LOGGER_LEVEL > log_lvl)) printf("fail | %5s (%d)| " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); }while (0)

#define LOGGER_DBG(log_lvl, msg, ...)   	\
	do { if ((LOGGER_ENABLE) && (LOGGER_LEVEL > log_lvl)) printf(" dbg | %5s (%d)| " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); }while (0)

#define LOGGER_RAW(log_lvl, msg, ...)    	\
	do { if ((LOGGER_ENABLE) && (LOGGER_LEVEL > log_lvl)) printf(msg "\n", ##__VA_ARGS__); }while (0)

#define LOGGER_HEX(log_lvl, ...)        \
    do { if ((LOGGER_ENABLE) && (LOGGER_LEVEL > log_lvl)) sslDiag_printHex(__VA_ARGS__); }while (0)

#define LOGGER_HEX_NAME(log_lvl, ...)        \
    do { if ((LOGGER_ENABLE) && (LOGGER_LEVEL > log_lvl)) sslDiag_printHexData(__VA_ARGS__); }while (0)
#endif /* _LOGGER_H_ */
