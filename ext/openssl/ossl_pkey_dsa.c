/*
 * $Id: ossl_pkey_dsa.c 28004 2010-05-24 23:58:49Z shyouhei $
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#if !defined(OPENSSL_NO_DSA)

#include "ossl.h"

#define GetPKeyDSA(obj, pkey) do { \
    GetPKey(obj, pkey); \
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_DSA) { /* PARANOIA? */ \
	ossl_raise(rb_eRuntimeError, "THIS IS NOT A DSA!"); \
    } \
} while (0)
#define GetDSA(obj, dsa) do { \
    EVP_PKEY *_pkey; \
    GetPKeyDSA((obj), _pkey); \
    (dsa) = EVP_PKEY_get0_DSA(_pkey); \
} while (0)

static inline int
DSA_HAS_PRIVATE(DSA *dsa)
{
    const BIGNUM *bn;
    DSA_get0_key(dsa, NULL, &bn);
    return !!bn;
}

#define DSA_PRIVATE(obj,dsa) (DSA_HAS_PRIVATE(dsa)||OSSL_PKEY_IS_PRIVATE(obj))

/*
 * Classes
 */
VALUE cDSA;
VALUE eDSAError;

/*
 * Public
 */
static VALUE
dsa_instance(VALUE klass, DSA *dsa)
{
    EVP_PKEY *pkey;
    VALUE obj;
	
    if (!dsa) {
	return Qfalse;
    }
    if (!(pkey = EVP_PKEY_new())) {
	return Qfalse;
    }
    if (!EVP_PKEY_assign_DSA(pkey, dsa)) {
	EVP_PKEY_free(pkey);
	return Qfalse;
    }
    WrapPKey(klass, obj, pkey);

    return obj;
}

VALUE
ossl_dsa_new(EVP_PKEY *pkey)
{
    VALUE obj;

    if (!pkey) {
	obj = dsa_instance(cDSA, DSA_new());
    } else {
	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_DSA) {
	    ossl_raise(rb_eTypeError, "Not a DSA key!");
	}
	WrapPKey(cDSA, obj, pkey);
    }
    if (obj == Qfalse) {
	ossl_raise(eDSAError, NULL);
    }

    return obj;
}

/*
 * Private
 */
static DSA *
dsa_generate(int size)
{
    DSA *dsa;
    unsigned char seed[20];
    int seed_len = 20, counter;
    unsigned long h;

    if (!RAND_bytes(seed, seed_len)) {
	return 0;
    }
    dsa = DSA_generate_parameters(size, seed, seed_len, &counter, &h,
	    rb_block_given_p() ? ossl_generate_cb : NULL,
	    NULL);
    if(!dsa) return 0;

    if (!DSA_generate_key(dsa)) {
	DSA_free(dsa);
	return 0;
    }

    return dsa;
}

/*
 *  call-seq:
 *    DSA.generate(size) -> dsa
 *
 *  === Parameters
 *  * +size+ is an integer representing the desired key size.
 *
 */
static VALUE
ossl_dsa_s_generate(VALUE klass, VALUE size)
{
    DSA *dsa = dsa_generate(NUM2INT(size)); /* err handled by dsa_instance */
    VALUE obj = dsa_instance(klass, dsa);

    if (obj == Qfalse) {
	DSA_free(dsa);
	ossl_raise(eDSAError, NULL);
    }

    return obj;
}

/*
 *  call-seq:
 *    DSA.new([size | string [, pass]) -> dsa
 *
 *  === Parameters
 *  * +size+ is an integer representing the desired key size.
 *  * +string+ contains a DER or PEM encoded key.
 *  * +pass+ is a string that contains a optional password.
 *
 *  === Examples
 *  * DSA.new -> dsa
 *  * DSA.new(1024) -> dsa
 *  * DSA.new(File.read('dsa.pem')) -> dsa
 *  * DSA.new(File.read('dsa.pem'), 'mypassword') -> dsa
 *
 */
static VALUE
ossl_dsa_initialize(int argc, VALUE *argv, VALUE self)
{
    EVP_PKEY *pkey;
    DSA *dsa;
    BIO *in;
    char *passwd = NULL;
    VALUE arg, pass;
	
    GetPKey(self, pkey);
    if(rb_scan_args(argc, argv, "02", &arg, &pass) == 0) {
        dsa = DSA_new();
    }
    else if (FIXNUM_P(arg)) {
	if (!(dsa = dsa_generate(FIX2INT(arg)))) {
	    ossl_raise(eDSAError, NULL);
	}
    }
    else {
	if (!NIL_P(pass)) passwd = StringValuePtr(pass);
	arg = ossl_to_der_if_possible(arg);
	in = ossl_obj2bio(arg);
	dsa = PEM_read_bio_DSAPrivateKey(in, NULL, ossl_pem_passwd_cb, passwd);
	if (!dsa) {
	    BIO_reset(in);
	    dsa = PEM_read_bio_DSAPublicKey(in, NULL, NULL, NULL);
	}
	if (!dsa) {
	    BIO_reset(in);
	    dsa = PEM_read_bio_DSA_PUBKEY(in, NULL, NULL, NULL);
	}
	if (!dsa) {
	    BIO_reset(in);
	    dsa = d2i_DSAPrivateKey_bio(in, NULL);
	}
	if (!dsa) {
	    BIO_reset(in);
	    dsa = d2i_DSA_PUBKEY_bio(in, NULL);
	}
	BIO_free(in);
	if (!dsa) ossl_raise(eDSAError, "Neither PUB key nor PRIV key:");
    }
    if (!EVP_PKEY_assign_DSA(pkey, dsa)) {
	DSA_free(dsa);
	ossl_raise(eDSAError, NULL);
    }

    return self;
}

/*
 *  call-seq:
 *    dsa.public? -> true | false
 *
 */
static VALUE
ossl_dsa_is_public(VALUE self)
{
    DSA *dsa;
    const BIGNUM *bn;

    GetDSA(self, dsa);
    DSA_get0_key(dsa, &bn, NULL);

    return bn ? Qtrue : Qfalse;
}

/*
 *  call-seq:
 *    dsa.private? -> true | false
 *
 */
static VALUE
ossl_dsa_is_private(VALUE self)
{
    DSA *dsa;
	
    GetDSA(self, dsa);
	
    return (DSA_PRIVATE(self, dsa)) ? Qtrue : Qfalse;
}

/*
 *  call-seq:
 *    dsa.to_pem([cipher, password]) -> aString
 *
 *  === Parameters
 *  +cipher+ is an OpenSSL::Cipher.
 *  +password+ is a string containing your password.
 *
 *  === Examples
 *  * DSA.to_pem -> aString
 *  * DSA.to_pem(cipher, 'mypassword') -> aString
 *
 */
static VALUE
ossl_dsa_export(int argc, VALUE *argv, VALUE self)
{
    DSA *dsa;
    BIO *out;
    const EVP_CIPHER *ciph = NULL;
    char *passwd = NULL;
    VALUE cipher, pass, str;

    GetDSA(self, dsa);
    rb_scan_args(argc, argv, "02", &cipher, &pass);
    if (!NIL_P(cipher)) {
	ciph = GetCipherPtr(cipher);
	if (!NIL_P(pass)) {
	    passwd = StringValuePtr(pass);
	}
    }
    if (!(out = BIO_new(BIO_s_mem()))) {
	ossl_raise(eDSAError, NULL);
    }
    if (DSA_HAS_PRIVATE(dsa)) {
	if (!PEM_write_bio_DSAPrivateKey(out, dsa, ciph,
					 NULL, 0, ossl_pem_passwd_cb, passwd)){
	    BIO_free(out);
	    ossl_raise(eDSAError, NULL);
	}
    } else {
	if (!PEM_write_bio_DSAPublicKey(out, dsa)) {
	    BIO_free(out);
	    ossl_raise(eDSAError, NULL);
	}
    }
    str = ossl_membio2str(out);

    return str;
}

/*
 *  call-seq:
 *    dsa.to_der -> aString
 *
 */
static VALUE
ossl_dsa_to_der(VALUE self)
{
    DSA *dsa;
    int (*i2d_func)_((DSA*, unsigned char**));
    unsigned char *p;
    long len;
    VALUE str;

    GetDSA(self, dsa);
    if(DSA_HAS_PRIVATE(dsa))
	i2d_func = (int(*)_((DSA*,unsigned char**)))i2d_DSAPrivateKey;
    else
	i2d_func = i2d_DSA_PUBKEY;
    if((len = i2d_func(dsa, NULL)) <= 0)
	ossl_raise(eDSAError, NULL);
    str = rb_str_new(0, len);
    p = RSTRING_PTR(str);
    if(i2d_func(dsa, &p) < 0)
	ossl_raise(eDSAError, NULL);
    ossl_str_adjust(str, p);

    return str;
}

/*
 *  call-seq:
 *    dsa.params -> hash
 *
 * Stores all parameters of key to the hash
 * INSECURE: PRIVATE INFORMATIONS CAN LEAK OUT!!!
 * Don't use :-)) (I's up to you)
 */
static VALUE
ossl_dsa_get_params(VALUE self)
{
    DSA *dsa;
    VALUE hash;
    const BIGNUM *p, *q, *g, *pub_key, *priv_key;

    GetDSA(self, dsa);
    DSA_get0_pqg(dsa, &p, &q, &g);
    DSA_get0_key(dsa, &pub_key, &priv_key);

    hash = rb_hash_new();

    rb_hash_aset(hash, rb_str_new2("p"), ossl_bn_new(p));
    rb_hash_aset(hash, rb_str_new2("q"), ossl_bn_new(q));
    rb_hash_aset(hash, rb_str_new2("g"), ossl_bn_new(g));
    rb_hash_aset(hash, rb_str_new2("pub_key"), ossl_bn_new(pub_key));
    rb_hash_aset(hash, rb_str_new2("priv_key"), ossl_bn_new(priv_key));
    
    return hash;
}

/*
 *  call-seq:
 *    dsa.to_text -> aString
 *
 * Prints all parameters of key to buffer
 * INSECURE: PRIVATE INFORMATIONS CAN LEAK OUT!!!
 * Don't use :-)) (I's up to you)
 */
static VALUE
ossl_dsa_to_text(VALUE self)
{
    DSA *dsa;
    BIO *out;
    VALUE str;

    GetDSA(self, dsa);
    if (!(out = BIO_new(BIO_s_mem()))) {
	ossl_raise(eDSAError, NULL);
    }
    if (!DSA_print(out, dsa, 0)) { /* offset = 0 */
	BIO_free(out);
	ossl_raise(eDSAError, NULL);
    }
    str = ossl_membio2str(out);

    return str;
}

/*
 *  call-seq:
 *    dsa.public_key -> aDSA
 *
 * Makes new instance DSA PUBLIC_KEY from PRIVATE_KEY
 */
static VALUE
ossl_dsa_to_public_key(VALUE self)
{
    EVP_PKEY *pkey;
    DSA *dsa;
    VALUE obj;
	
    GetPKeyDSA(self, pkey);
    /* err check performed by dsa_instance */
#define DSAPublicKey_dup(dsa) (DSA *)ASN1_dup( \
        (i2d_of_void *)i2d_DSAPublicKey, (d2i_of_void *)d2i_DSAPublicKey, (char *)(dsa))
    dsa = DSAPublicKey_dup(EVP_PKEY_get0_DSA(pkey));
#undef DSAPublicKey_dup
    obj = dsa_instance(CLASS_OF(self), dsa);
    if (obj == Qfalse) {
	DSA_free(dsa);
	ossl_raise(eDSAError, NULL);
    }
    return obj;
}

#define ossl_dsa_buf_size2(dsa) (DSA_size(dsa)+16)

/*
 *  call-seq:
 *    dsa.syssign(string) -> aString
 *
 */
static VALUE
ossl_dsa_sign(VALUE self, VALUE data)
{
    DSA *dsa;
    const BIGNUM *dsa_q;
    int buf_len;
    VALUE str;

    GetDSA(self, dsa);
    DSA_get0_pqg(dsa, NULL, &dsa_q, NULL);
    if (!dsa_q)
        ossl_raise(eDSAError, "incomplete DSA");
    StringValue(data);
    if (!DSA_PRIVATE(self, dsa)) {
	ossl_raise(eDSAError, "Private DSA key needed!");
    }
    str = rb_str_new(0, ossl_dsa_buf_size2(dsa));
    if (!DSA_sign(0, RSTRING_PTR(data), RSTRING_LEN(data), RSTRING_PTR(str),
		  &buf_len, dsa)) { /* type is ignored (0) */
	ossl_raise(eDSAError, NULL);
    }
    rb_str_set_len(str, buf_len);

    return str;
}

/*
 *  call-seq:
 *    dsa.sysverify(digest, sig) -> true | false
 *
 */
static VALUE
ossl_dsa_verify(VALUE self, VALUE digest, VALUE sig)
{
    DSA *dsa;
    int ret;

    GetDSA(self, dsa);
    StringValue(digest);
    StringValue(sig);
    /* type is ignored (0) */
    ret = DSA_verify(0, RSTRING_PTR(digest), RSTRING_LEN(digest),
		     RSTRING_PTR(sig), RSTRING_LEN(sig), dsa);
    if (ret < 0) {
	ossl_raise(eDSAError, NULL);
    }
    else if (ret == 1) {
	return Qtrue;
    }

    return Qfalse;
}

/*
 * Document-method: OpenSSL::PKey::DSA#set_pqg
 * call-seq:
 *   dsa.set_pqg(p, q, g) -> self
 *
 * Sets _p_, _q_, _g_ to the DSA instance.
 */
OSSL_PKEY_BN_DEF3(dsa, DSA, pqg, p, q, g)
/*
 * Document-method: OpenSSL::PKey::DSA#set_key
 * call-seq:
 *   dsa.set_key(pub_key, priv_key) -> self
 *
 * Sets _pub_key_ and _priv_key_ for the DSA instance. _priv_key_ may be +nil+.
 */
OSSL_PKEY_BN_DEF2(dsa, DSA, key, pub_key, priv_key)

/*
 * INIT
 */
void
Init_ossl_dsa()
{
#if 0 /* let rdoc know about mOSSL and mPKey */
    mOSSL = rb_define_module("OpenSSL");
    mPKey = rb_define_module_under(mOSSL, "PKey");
#endif

    eDSAError = rb_define_class_under(mPKey, "DSAError", ePKeyError);

    cDSA = rb_define_class_under(mPKey, "DSA", cPKey);
	
    rb_define_singleton_method(cDSA, "generate", ossl_dsa_s_generate, 1);
    rb_define_method(cDSA, "initialize", ossl_dsa_initialize, -1);

    rb_define_method(cDSA, "public?", ossl_dsa_is_public, 0);
    rb_define_method(cDSA, "private?", ossl_dsa_is_private, 0);
    rb_define_method(cDSA, "to_text", ossl_dsa_to_text, 0);
    rb_define_method(cDSA, "export", ossl_dsa_export, -1);
    rb_define_alias(cDSA, "to_pem", "export");
    rb_define_alias(cDSA, "to_s", "export");
    rb_define_method(cDSA, "to_der", ossl_dsa_to_der, 0);
    rb_define_method(cDSA, "public_key", ossl_dsa_to_public_key, 0);
    rb_define_method(cDSA, "syssign", ossl_dsa_sign, 1);
    rb_define_method(cDSA, "sysverify", ossl_dsa_verify, 2);

    DEF_OSSL_PKEY_BN(cDSA, dsa, p);
    DEF_OSSL_PKEY_BN(cDSA, dsa, q);
    DEF_OSSL_PKEY_BN(cDSA, dsa, g);
    DEF_OSSL_PKEY_BN(cDSA, dsa, pub_key);
    DEF_OSSL_PKEY_BN(cDSA, dsa, priv_key);
    rb_define_method(cDSA, "set_pqg", ossl_dsa_set_pqg, 3);
    rb_define_method(cDSA, "set_key", ossl_dsa_set_key, 2);

    rb_define_method(cDSA, "params", ossl_dsa_get_params, 0);
}

#else /* defined NO_DSA */
void
Init_ossl_dsa()
{
}
#endif /* NO_DSA */
