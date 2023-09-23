#if !defined(_BNET_OPENSSL_MISSING_H_)
#define _BNET_OPENSSL_MISSING_H_

#if !defined(HAVE_EVP_PKEY_UP_REF)
#  define EVP_PKEY_up_ref(x) \
        CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_EVP_PKEY);
#endif

#if !defined(HAVE_SSL_CTX_GET_CIPHERS)
#  define SSL_CTX_get_ciphers(ctx) ((ctx)->cipher_list)
#endif

#if !defined(HAVE_X509_CRL_UP_REF)
#  define X509_CRL_up_ref(x) \
	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_X509_CRL);
#endif

#if !defined(HAVE_X509_GET0_NOTBEFORE)
#  define X509_get0_notBefore(x) X509_get_notBefore(x)
#  define X509_get0_notAfter(x) X509_get_notAfter(x)
#  define X509_CRL_get0_lastUpdate(x) X509_CRL_get_lastUpdate(x)
#  define X509_CRL_get0_nextUpdate(x) X509_CRL_get_nextUpdate(x)
#  define X509_set1_notBefore(x, t) X509_set_notBefore(x, t)
#  define X509_set1_notAfter(x, t) X509_set_notAfter(x, t)
#  define X509_CRL_set1_lastUpdate(x, t) X509_CRL_set_lastUpdate(x, t)
#  define X509_CRL_set1_nextUpdate(x, t) X509_CRL_set_nextUpdate(x, t)
#endif


#if !defined(HAVE_OPAQUE_OPENSSL)
#define IMPL_PKEY_GETTER(_type, _name) \
static inline _type *EVP_PKEY_get0_##_type(EVP_PKEY *pkey) { \
        return pkey->pkey._name; }
#define IMPL_KEY_ACCESSOR2(_type, _group, a1, a2, _fail_cond) \
static inline void _type##_get0_##_group(_type *obj, BIGNUM **a1, BIGNUM **a2) { \
        if (a1) *a1 = obj->a1; \
        if (a2) *a2 = obj->a2; } \
static inline int _type##_set0_##_group(_type *obj, BIGNUM *a1, BIGNUM *a2) { \
        if (_fail_cond) return 0; \
        BN_clear_free(obj->a1); obj->a1 = a1; \
        BN_clear_free(obj->a2); obj->a2 = a2; \
        return 1; }
#define IMPL_KEY_ACCESSOR3(_type, _group, a1, a2, a3, _fail_cond) \
static inline void _type##_get0_##_group(_type *obj, BIGNUM **a1, BIGNUM **a2, BIGNUM **a3) { \
        if (a1) *a1 = obj->a1; \
        if (a2) *a2 = obj->a2; \
        if (a3) *a3 = obj->a3; } \
static inline int _type##_set0_##_group(_type *obj, BIGNUM *a1, BIGNUM *a2, BIGNUM *a3) { \
        if (_fail_cond) return 0; \
        BN_clear_free(obj->a1); obj->a1 = a1; \
        BN_clear_free(obj->a2); obj->a2 = a2; \
        BN_clear_free(obj->a3); obj->a3 = a3; \
        return 1; }

#if !defined(OPENSSL_NO_RSA)
IMPL_PKEY_GETTER(RSA, rsa)
IMPL_KEY_ACCESSOR3(RSA, key, n, e, d, (n == obj->n || e == obj->e || (obj->d && e == obj->d)))
IMPL_KEY_ACCESSOR2(RSA, factors, p, q, (p == obj->p || q == obj->q))
IMPL_KEY_ACCESSOR3(RSA, crt_params, dmp1, dmq1, iqmp, (dmp1 == obj->dmp1 || dmq1 == obj->dmq1 || iqmp == obj->iqmp))
#endif

#if !defined(OPENSSL_NO_DSA)
IMPL_PKEY_GETTER(DSA, dsa)
IMPL_KEY_ACCESSOR2(DSA, key, pub_key, priv_key, (pub_key == obj->pub_key || (obj->priv_key && priv_key == obj->priv_key)))
IMPL_KEY_ACCESSOR3(DSA, pqg, p, q, g, (p == obj->p || q == obj->q || g == obj->g))
#endif

#if !defined(OPENSSL_NO_DH)
IMPL_PKEY_GETTER(DH, dh)
IMPL_KEY_ACCESSOR2(DH, key, pub_key, priv_key, (pub_key == obj->pub_key || (obj->priv_key && priv_key == obj->priv_key)))
IMPL_KEY_ACCESSOR3(DH, pqg, p, q, g, (p == obj->p || q == obj->q || g == obj->g))
static inline ENGINE *DH_get0_engine(DH *dh) { return dh->engine; }
#endif

#if !defined(OPENSSL_NO_EC)
IMPL_PKEY_GETTER(EC_KEY, ec)
#endif

#undef IMPL_PKEY_GETTER
#undef IMPL_KEY_ACCESSOR2
#undef IMPL_KEY_ACCESSOR3
#endif /* HAVE_OPAQUE_OPENSSL */


#if defined(HAVE_OPAQUE_OPENSSL)
// These functions were  left undefined by openssl 1.1.x, and should be using helper functions to access as needed.
#if 0
struct x509_store_ctx_st {      /* X509_STORE_CTX */
    X509_STORE *ctx;
    /* The following are set by the caller */
    /* The cert to check */
    X509 *cert;
    /* chain of X509s - untrusted - passed in */
    STACK_OF(X509) *untrusted;
    /* set of CRLs passed in */
    STACK_OF(X509_CRL) *crls;
    X509_VERIFY_PARAM *param;
    /* Other info for use with get_issuer() */
    void *other_ctx;
    /* Callbacks for various operations */
    /* called to verify a certificate */
    int (*verify) (X509_STORE_CTX *ctx);
    /* error callback */
    int (*verify_cb) (int ok, X509_STORE_CTX *ctx);
    /* get issuers cert from ctx */
    int (*get_issuer) (X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
    /* check issued */
    int (*check_issued) (X509_STORE_CTX *ctx, X509 *x, X509 *issuer);
    /* Check revocation status of chain */
    int (*check_revocation) (X509_STORE_CTX *ctx);
    /* retrieve CRL */
    int (*get_crl) (X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x);
    /* Check CRL validity */
    int (*check_crl) (X509_STORE_CTX *ctx, X509_CRL *crl);
    /* Check certificate against CRL */
    int (*cert_crl) (X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x);
    /* Check policy status of the chain */
    int (*check_policy) (X509_STORE_CTX *ctx);
    STACK_OF(X509) *(*lookup_certs) (X509_STORE_CTX *ctx, X509_NAME *nm);
    STACK_OF(X509_CRL) *(*lookup_crls) (X509_STORE_CTX *ctx, X509_NAME *nm);
    int (*cleanup) (X509_STORE_CTX *ctx);
    /* The following is built up */
    /* if 0, rebuild chain */
    int valid;
    /* number of untrusted certs */
    int num_untrusted;
    /* chain of X509s - built up and trusted */
    STACK_OF(X509) *chain;
    /* Valid policy tree */
    X509_POLICY_TREE *tree;
    /* Require explicit policy value */
    int explicit_policy;
    /* When something goes wrong, this is why */
    int error_depth;
    int error;
    X509 *current_cert;
    /* cert currently being tested as valid issuer */
    X509 *current_issuer;
    /* current CRL */
    X509_CRL *current_crl;
    /* score of current CRL */
    int current_crl_score;
    /* Reason mask */
    unsigned int current_reasons;
    /* For CRL path validation: parent context */
    X509_STORE_CTX *parent;
    CRYPTO_EX_DATA ex_data;
    SSL_DANE *dane;
    /* signed via bare TA public key, rather than CA certificate */
    int bare_ta_signed;
};
struct dh_st {
    /*
     * This first argument is used to pick up errors when a DH is passed
     * instead of a EVP_PKEY
     */
    int pad;
    int version;
    BIGNUM *p;
    BIGNUM *g;
    int32_t length;             /* optional */
    BIGNUM *pub_key;            /* g^x % p */
    BIGNUM *priv_key;           /* x */
    int flags;
    BN_MONT_CTX *method_mont_p;
    /* Place holders if we want to do X9.42 DH */
    BIGNUM *q;
    BIGNUM *j;
    unsigned char *seed;
    int seedlen;
    BIGNUM *counter;
    int references;
    //CRYPTO_REF_COUNT references;
    CRYPTO_EX_DATA ex_data;
    const DH_METHOD *meth;
    ENGINE *engine;
    CRYPTO_RWLOCK *lock;
};
#endif /* 0 */
# if 0
typedef int CRYPTO_REF_COUNT;
#define TLS13_MAX_RESUMPTION_PSK_LENGTH      256
#define SSL_MAX_SSL_SESSION_ID_LENGTH           32
#define SSL_MAX_SID_CTX_LENGTH                  32
typedef struct ssl_cipher_st SSL_CIPHER;
#include <openssl/ssl.h>
struct ssl_session_st {
    int ssl_version;            /* what ssl version session info is being kept
                                 * in here? */
    size_t master_key_length;

    /* TLSv1.3 early_secret used for external PSKs */
    unsigned char early_secret[EVP_MAX_MD_SIZE];
    /*
     * For <=TLS1.2 this is the master_key. For TLS1.3 this is the resumption
     * PSK
     */
    unsigned char master_key[TLS13_MAX_RESUMPTION_PSK_LENGTH];
    /* session_id - valid? */
    size_t session_id_length;
    unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    /*
     * this is used to determine whether the session is being reused in the
     * appropriate context. It is up to the application to set this, via
     * SSL_new
     */
    size_t sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
# ifndef OPENSSL_NO_PSK
    char *psk_identity_hint;
    char *psk_identity;
# endif
    /*
     * Used to indicate that session resumption is not allowed. Applications
     * can also set this bit for a new session via not_resumable_session_cb
     * to disable session caching and tickets.
     */
    int not_resumable;
    /* This is the cert and type for the other end. */
    X509 *peer;
    int peer_type;
    /* Certificate chain peer sent. */
    STACK_OF(X509) *peer_chain;
    /*
     * when app_verify_callback accepts a session where the peer's
     * certificate is not ok, we must remember the error for session reuse:
     */
    long verify_result;         /* only for servers */
    CRYPTO_REF_COUNT references;
    long timeout;
    long time;
    unsigned int compress_meth; /* Need to lookup the method */
    const SSL_CIPHER *cipher;
    unsigned long cipher_id;    /* when ASN.1 loaded, this needs to be used to
                                 * load the 'cipher' structure */
    STACK_OF(SSL_CIPHER) *ciphers; /* ciphers offered by the client */
    CRYPTO_EX_DATA ex_data;     /* application specific data */
    /*
     * These are used to make removal of session-ids more efficient and to
     * implement a maximum cache size.
     */
    struct ssl_session_st *prev, *next;

    struct {
        char *hostname;
# ifndef OPENSSL_NO_EC
        size_t ecpointformats_len;
        unsigned char *ecpointformats; /* peer's list */
# endif                         /* OPENSSL_NO_EC */
        size_t supportedgroups_len;
        uint16_t *supportedgroups; /* peer's list */
    /* RFC4507 info */
        unsigned char *tick; /* Session ticket */
        size_t ticklen;      /* Session ticket length */
        /* Session lifetime hint in seconds */
        unsigned long tick_lifetime_hint;
        uint32_t tick_age_add;
        /* Max number of bytes that can be sent as early data */
        uint32_t max_early_data;
        /* The ALPN protocol selected for this session */
        unsigned char *alpn_selected;
        size_t alpn_selected_len;
        /*
         * Maximum Fragment Length as per RFC 4366.
         * If this value does not contain RFC 4366 allowed values (1-4) then
         * either the Maximum Fragment Length Negotiation failed or was not
         * performed at all.
         */
        uint8_t max_fragment_len_mode;
    } ext;
# ifndef OPENSSL_NO_SRP
    char *srp_username;
# endif
    unsigned char *ticket_appdata;
    size_t ticket_appdata_len;
    uint32_t flags;
    CRYPTO_RWLOCK *lock;
};
struct ocsp_cert_id_st {
    X509_ALGOR hashAlgorithm;
    ASN1_OCTET_STRING issuerNameHash;
    ASN1_OCTET_STRING issuerKeyHash;
    ASN1_INTEGER serialNumber;
};
struct X509_req_info_st {
    ASN1_ENCODING enc;          /* cached encoding of signed part */
    ASN1_INTEGER *version;      /* version, defaults to v1(0) so can be NULL */
    X509_NAME *subject;         /* certificate request DN */
    X509_PUBKEY *pubkey;        /* public key of request */
    /*
     * Zero or more attributes.
     * NB: although attributes is a mandatory field some broken
     * encodings omit it so this may be NULL in that case.
     */
    STACK_OF(X509_ATTRIBUTE) *attributes;
};
struct X509_req_st {
    X509_REQ_INFO req_info;     /* signed certificate request data */
    X509_ALGOR sig_alg;         /* signature algorithm */
    ASN1_BIT_STRING *signature; /* signature */
    CRYPTO_REF_COUNT references;
    CRYPTO_RWLOCK *lock;
};
struct x509_revoked_st {
    ASN1_INTEGER serialNumber; /* revoked entry serial number */
    ASN1_TIME *revocationDate;  /* revocation date */
    STACK_OF(X509_EXTENSION) *extensions;   /* CRL entry extensions: optional */
    /* decoded value of CRLissuer extension: set if indirect CRL */
    STACK_OF(GENERAL_NAME) *issuer;
    /* revocation reason: set to CRL_REASON_NONE if reason extension absent */
    int reason;
    /*
     * CRL entries are reordered for faster lookup of serial numbers. This
     * field contains the original load sequence for this entry.
     */
    int sequence;
};
#define X25519_KEYLEN        32
#define X448_KEYLEN          56
#define ED448_KEYLEN         57

#define MAX_KEYLEN  ED448_KEYLEN

typedef struct {
    unsigned char pubkey[MAX_KEYLEN];
    unsigned char *privkey;
} ECX_KEY;
struct evp_pkey_st {
    int type;
    int save_type;
    CRYPTO_REF_COUNT references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    ENGINE *pmeth_engine; /* If not NULL public key ENGINE to use */
    union {
        void *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
        ECX_KEY *ecx;           /* X25519, X448, Ed25519, Ed448 */
# endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */ ;
struct bn_gencb_st {
    unsigned int ver;           /* To handle binary (in)compatibility */
    void *arg;                  /* callback-specific data */
    union {
        /* if (ver==1) - handles old style callbacks */
        void (*cb_1) (int, int, void *);
        /* if (ver==2) - new callback style */
        int (*cb_2) (int, int, BN_GENCB *);
    } cb;
};
struct evp_md_ctx_st {
    const EVP_MD *digest;
    ENGINE *engine;             /* functional reference if 'digest' is
                                 * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
} /* EVP_MD_CTX */ ;
struct x509_attributes_st {
    ASN1_OBJECT *object;
    STACK_OF(ASN1_TYPE) *set;
};
struct X509_extension_st {
    ASN1_OBJECT *object;
    ASN1_BOOLEAN critical;
    ASN1_OCTET_STRING value;
};
struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    ENGINE *engine;             /* functional reference if 'cipher' is
                                 * ENGINE-provided */
    int encrypt;                /* encrypt or decrypt */
    int buf_len;                /* number we have left */
    unsigned char oiv[EVP_MAX_IV_LENGTH]; /* original iv */
    unsigned char iv[EVP_MAX_IV_LENGTH]; /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH]; /* saved partial block */
    int num;                    /* used by cfb/ofb/ctr mode */
    /* FIXME: Should this even exist? It appears unused */
    void *app_data;             /* application stuff */
    int key_len;                /* May change for variable length cipher */
    unsigned long flags;        /* Various flags */
    void *cipher_data;          /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
} /* EVP_CIPHER_CTX */ ;
// ruby-2.0.0-p648/ext/openssl/ossl_hmac.c - Fix hmac_final 
/* The current largest case is for SHA3-224 */
#define HMAC_MAX_MD_CBLOCK_SIZE     144
struct hmac_ctx_st {
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx;
    EVP_MD_CTX *i_ctx;
    EVP_MD_CTX *o_ctx;
    unsigned int key_length;
    unsigned char key[HMAC_MAX_MD_CBLOCK_SIZE];
};


//New ones
struct rsa_st {
    /*
     * The first parameter is used to pickup errors where this is passed
     * instead of an EVP_PKEY, it is set to 0
     */
    int pad;
    int32_t version;
    const RSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
    /* for multi-prime RSA, defined in RFC 8017 */
    STACK_OF(RSA_PRIME_INFO) *prime_infos;
    /* If a PSS only key this contains the parameter restrictions */
    RSA_PSS_PARAMS *pss;
    /* be careful using this if the RSA structure is shared */
    CRYPTO_EX_DATA ex_data;
    CRYPTO_REF_COUNT references;
    int flags;
    /* Used to cache montgomery values */
    BN_MONT_CTX *_method_mod_n;
    BN_MONT_CTX *_method_mod_p;
    BN_MONT_CTX *_method_mod_q;
    /*
     * all BIGNUM values are actually in the following data, if it is not
     * NULL
     */
    char *bignum_data;
    BN_BLINDING *blinding;
    BN_BLINDING *mt_blinding;
    CRYPTO_RWLOCK *lock;
};
struct dsa_st {
    /*
     * This first variable is used to pick up errors where a DSA is passed
     * instead of of a EVP_PKEY
     */
    int pad;
    int32_t version;
    BIGNUM *p;
    BIGNUM *q;                  /* == 20 */
    BIGNUM *g;
    BIGNUM *pub_key;            /* y public key */
    BIGNUM *priv_key;           /* x private key */
    int flags;
    /* Normally used to cache montgomery values */
    BN_MONT_CTX *method_mont_p;
    CRYPTO_REF_COUNT references;
    CRYPTO_EX_DATA ex_data;
    const DSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    CRYPTO_RWLOCK *lock;
};
#endif /* 0 */
#endif /* OPAQUE */

#if !defined(HAVE_BN_GENCB_NEW)
#  define BN_GENCB_new() ((BN_GENCB *)OPENSSL_malloc(sizeof(BN_GENCB)))
#endif

#if !defined(HAVE_BN_GENCB_FREE)
#  define BN_GENCB_free(cb) OPENSSL_free(cb)
#endif

#if !defined(HAVE_BN_GENCB_GET_ARG)
#  define BN_GENCB_get_arg(cb) (cb)->arg
#endif

#if !defined(HAVE_EVP_MD_CTX_FREE)
#  define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

#if !defined(HAVE_EVP_MD_CTX_NEW)
#  define EVP_MD_CTX_new EVP_MD_CTX_create
#endif

#if !defined(HAVE_HMAC_CTX_NEW)
HMAC_CTX *ossl_HMAC_CTX_new(void);
#  define HMAC_CTX_new ossl_HMAC_CTX_new
#endif

#if !defined(HAVE_HMAC_CTX_FREE)
void ossl_HMAC_CTX_free(HMAC_CTX *);
#  define HMAC_CTX_free ossl_HMAC_CTX_free
#endif

#if !defined(HAVE_SSL_SESSION_GET_PROTOCOL_VERSION)
#  define SSL_SESSION_get_protocol_version(s) ((s)->ssl_version)
#endif

#if !defined(HAVE_SSL_SESSION_UP_REF)
#  define SSL_SESSION_up_ref(x) \
	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_SSL_SESSION);
#endif

#if !defined(HAVE_X509_GET0_TBS_SIGALG)
#  define X509_get0_tbs_sigalg(x) ((x)->cert_info->signature)
#endif

#if !defined(HAVE_X509_REVOKED_GET0_REVOCATIONDATE)
#  define X509_REVOKED_get0_revocationDate(x) ((x)->revocationDate)
#endif

#if !defined(HAVE_X509_REVOKED_GET0_SERIALNUMBER)
#  define X509_REVOKED_get0_serialNumber(x) ((x)->serialNumber)
#endif

#if !defined(HAVE_X509_STORE_CTX_GET0_CERT)
#  define X509_STORE_CTX_get0_cert(x) ((x)->cert)
#endif

#if !defined(HAVE_X509_STORE_CTX_GET0_STORE)
#  define X509_STORE_CTX_get0_store(x) ((x)->ctx)
#endif

#if !defined(HAVE_X509_STORE_CTX_GET0_UNTRUSTED)
#  define X509_STORE_CTX_get0_untrusted(x) ((x)->untrusted)
#endif

#if !defined(HAVE_X509_UP_REF)
#  define X509_up_ref(x) \
        CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_X509);
#endif


/*
 * Convert binary string to hex string. The caller is responsible for
 * ensuring out has (2 * len) bytes of capacity.
 */
void ossl_bin2hex(unsigned char *in, char *out, size_t len);

#endif /* _BNET_OPENSSL_MISSING_H_ */

