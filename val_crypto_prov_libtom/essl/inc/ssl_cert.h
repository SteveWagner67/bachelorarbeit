/*
 * ssl_cert.h
 *
 *  Created on: Oct 3, 2014
 *      Author: ookie
 */

#ifndef SSL_CERT_H_
#define SSL_CERT_H_

/*** Defines ****************************************************************/

#ifndef SSL_CERT_PATHLEN_INVALID
/*! This value indicates the initial and invalid value of pathLenConstraint */
#define SSL_CERT_PATHLEN_INVALID     -1
#endif

#ifndef SSL_CERT_PATHLEN_INFINITE
/*! This value indicates that pathLenConstraint
 * allows an infinite number of CAs to follow
 */
#define SSL_CERT_PATHLEN_INFINITE    -2
#endif

/*!
 * Return values of the SSL_CAcert_X() functions
 */
typedef enum E_SSL_CERT_ERRORS
{
    /* All OK */
    E_SSL_CERT_OK = 0,
    /*!
     * Decoding was successful but there was no buffer given to save the subject.
     * RSA Public Key was extracted successfully, so this error can be ignored.
     */
    E_SSL_CERT_BUFFER_NOT_SET,
    /* General error code  */
    E_SSL_CERT_ERR = 0x100,
    /*=========================================================================*/
    /*
     * verification errors by CA certificate initialisation routine
     */
    /*=========================================================================*/
    /* decoding of the certificate failed */
    E_SSL_CERT_ERR_DECODING_FAILED,
    /* s_basicConstr indicate that this certificate is not a CA */
    E_SSL_CERT_ERR_NO_CA,
    /* pathLenConstraint says that no further CA's are allowed */
    E_SSL_CERT_ERR_PATHLENCONSTRAINT,
    /* s_basicConstr field was missing in extensions */
    E_SSL_CERT_ERR_BASICCONSTRAINTS,
    /* No Root CA certificate has been found in the list */
    E_SSL_CERT_ERR_NO_ROOT_AVAILABLE,
    /* This is a self-signed certificate */
    E_SSL_CERT_ERR_SELF_SIGNED,
    /* The public key could not be extracted from the certificate */
    E_SSL_CERT_ERR_PUBLIC_KEY,
    /* The verification of the certificate failed */
    E_SSL_CERT_ERR_VERIF_FAILED,
    /*!
     * The decoding was successful but the buffer that has been given is
     * too small to hold the subject.
     * RSA Public Key has been imported successful, so this error can be ignored
     * if the CA subject isn't required.
     */
    E_SSL_CERT_ERR_SMALL_BUFFER,
    /*=========================================================================*/
    /*
     * verification errors by:         Certificate verification routine
     */
    /*=========================================================================*/
    /* The hashtype that is used, is not supported*/
    E_SSL_CERT_ERR_INVALID_HASH,
    /* The verification process failed */
    E_SSL_CERT_ERR_PROCESS_FAILED,
    /* The verification failed */
    E_SSL_CERT_ERR_VERIFICATION_FAILED,
    /* The certificate has been signed by a CA that is not known to us */
    E_SSL_CERT_ERR_CA_NOT_KNOWN,
    /*=========================================================================*/
    /*
     * decoding errors by:             Extension decoding routines
     */
    /*=========================================================================*/
    /* Something went wrong when decoding the s_basicConstr field */
    E_SSL_CERT_ERR_EXT_BASIC_CONSTRAINTS,
    /* The CA field is missing in the s_basicConstr field */
    E_SSL_CERT_ERR_EXT_BC_CA_MISSING,
    /* The l_pathLenConstr field in s_basicConstr was too long for an int */
    E_SSL_CERT_ERR_EXT_BC_PATHLEN_ERR,
    /* Something went wrong when decoding the s_keyUsage field */
    E_SSL_CERT_ERR_EXT_KEYUSAGE,
    /* The s_extKeyUsage field was malformed */
    E_SSL_CERT_ERR_EXT_EXTKEYUSAGE,
    /* The netscape-cert-type field was malformed */
    E_SSL_CERT_ERR_EXT_NETSCAPE_CERTTYPE,
    /*=========================================================================*/
    /*
     * decoding errors by:             signature field decoding routine
     */
    /*=========================================================================*/
    /* The signature field was not properly formed */
    E_SSL_CERT_ERR_STRUCT_FAIL,
    /* The Object ID was missing */
    E_SSL_CERT_ERR_NO_OBJECT,
    /* No error, but there are more elements available */
    E_SSL_CERT_MORE_ELEMENTS_AVAILABLE,
} e_sslCertErr_t;

/*
 * decoded public Key certificate structure
 */
typedef struct tagKeyCertInfo
{
    uint32_t l_ver;
    s_sslIntStr_t s_serialN;
    int32_t l_sigAlgOId;
    s_sslDerValid_t s_validity;

    s_sslOctetStr_t s_octIssuer;
    s_sslOctetStr_t s_octSubj;

    s_sslOctetStr_t s_octPubKey;

    s_sslOctetStr_t s_octIssuerUId;
    s_sslOctetStr_t s_octSubjUId;

    s_sslOctetStr_t s_octExts;

    s_sslOctetStr_t s_octCert;
    s_sslOctetStr_t s_octTbsCert;
    s_sslBitStr_t s_sign;

} s_sslKeyCertInfo_t;

typedef struct tagKeyCertExtensions
{
    /* ITU-T X.509 - Ch. 8.4.2.1
     * - if the value of cA is not set to true then the certified public key
     *      shall not be used to verify a certificate signature
     * ??? if the value of cA is set to true and pathLenConstraint is present
     *      then the certificate-using system shall check that the
     *      certification path being processed is consistent with the value
     *      of pathLenConstraint
     */
    struct tagBasicConstraints
    {
        /*! The cA component indicates if the certified public key may
         * be used to verify certificate signatures
         */
        uint8_t c_isCa;
        /*!
         * The pathLenConstraint component ... gives the maximum number of
         * CA-certificates that may follow this certificate in a
         * certification path
         * Value 0 indicates that the subject of this certificate may issue
         * certificates only to end-entities and not to further CAs.
         * If no pathLenConstraint field appears in any certificate of a
         * certification path, there is no limit to the allowed length
         * of the certification path.
         * \sa SSL_CERT_PATHLEN_INVALID
         * \sa SSL_CERT_PATHLEN_INFINITE
         */
        int32_t l_pathlen;
    } s_basicConstr;

    /* ITU-T X.509 - Ch. 8.2.2.3
     * The bit keyCertSign is for use in CA-certificates only. If KeyUsage
     * is set to keyCertSign and the basic constraints extension is present in
     * the same certificate, the value of the cA component of that extension
     * shall be set to TRUE.
     */
    struct tagKeyUsage
    {
        /*! keyCertSign (bit 5): for verifying a
         * CA's signature on certificates;
         */
        uint8_t c_keyCertSign;
    } s_keyUsage;

    /* ITU-T X.509 - Ch. 8.2.2.4
     * This field indicates one or more purposes for which the certified
     * public key may be used, in addition to or in place of the basic purposes
     * indicated in the key usage extension field.
     */
    struct tagExtendedKeyUsage
    {
        /*! clientAuth is indicated by OID 1.3.6.1.5.5.7.3.2 */
        uint8_t c_cliAuth;
    } s_extKeyUsage;

    /* Netscape Certificate s_octExts - Communicator 4.0 Version
     *
     * netscape-cert-type:
     *     This extension can be used to limit the applications for a certificate.
     *     If the extension exists in a certificate, it will limit the uses of the
     *     certificate to those specified.  If the extension is not present, the
     *     certificate can be used for all applications except Object Signing.
     */
    struct tagNetscapeCertType
    {
        /*! bit-0   SSL client - this cert is certified for
         *  SSL client authentication use
         */
        uint8_t c_sslCli;
        /*! bit-1   SSL server - this cert is certified for
         *  SSL server authentication use
         */
        uint8_t c_sslSrv;
        /*! bit-5   SSL CA - this cert is certified for
         *  issuing certs for SSL use
         */
        uint8_t c_sslCa;
    } s_netscCertType;
} s_sslKeyCertExt_t;

typedef struct tagKeyCertSubject
{
    int type;
    s_sslGenStr_t strData;
} s_sslKeyCertSubj_t;

#endif /* SSL_CERT_H_ */
