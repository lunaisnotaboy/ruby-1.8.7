/*
 * $Id: ossl_pkey.c 28004 2010-05-24 23:58:49Z shyouhei $
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

/*
 * Classes
 */
VALUE mPKey;
VALUE cPKey;
VALUE ePKeyError;
ID id_private_q;

/*
 * callback for generating keys
 */
void
ossl_generate_cb(int p, int n, void *arg)
{
    VALUE ary;

    ary = rb_ary_new2(2);
    rb_ary_store(ary, 0, INT2NUM(p));
    rb_ary_store(ary, 1, INT2NUM(n));

    rb_yield(ary);
}

/*
 * Public
 */
VALUE
ossl_pkey_new(EVP_PKEY *pkey)
{
    if (!pkey) {
	ossl_raise(ePKeyError, "Cannot make new key from NULL.");
    }
    switch (EVP_PKEY_base_id(pkey)) {
#if !defined(OPENSSL_NO_RSA)
    case EVP_PKEY_RSA:
	return ossl_rsa_new(pkey);
#endif
#if !defined(OPENSSL_NO_DSA)
    case EVP_PKEY_DSA:
	return ossl_dsa_new(pkey);
#endif
#if !defined(OPENSSL_NO_DH)
    case EVP_PKEY_DH:
	return ossl_dh_new(pkey);
#endif
#if !defined(OPENSSL_NO_EC) && (OPENSSL_VERSION_NUMBER >= 0x0090802fL)
    case EVP_PKEY_EC:
	return ossl_ec_new(pkey);
#endif
    default:
	ossl_raise(ePKeyError, "unsupported key type");
    }
    return Qnil; /* not reached */
}

VALUE
ossl_pkey_new_from_file(VALUE filename)
{
    FILE *fp;
    EVP_PKEY *pkey;

    SafeStringValue(filename);
    if (!(fp = fopen(RSTRING_PTR(filename), "r"))) {
	ossl_raise(ePKeyError, "%s", strerror(errno));
    }

    pkey = PEM_read_PrivateKey(fp, NULL, ossl_pem_passwd_cb, NULL);
    fclose(fp);
    if (!pkey) {
	ossl_raise(ePKeyError, NULL);
    }

    return ossl_pkey_new(pkey);
}

void
ossl_pkey_check_public_key(const EVP_PKEY *pkey)
{
    void *ptr;
    const BIGNUM *n, *e, *pubkey;

    if (EVP_PKEY_missing_parameters(pkey))
        ossl_raise(ePKeyError, "parameters missing");

    /* OpenSSL < 1.1.0 takes non-const pointer */
    ptr = EVP_PKEY_get0((EVP_PKEY *)pkey);
    switch (EVP_PKEY_base_id(pkey)) {
      case EVP_PKEY_RSA:
        RSA_get0_key(ptr, &n, &e, NULL);
        if (n && e)
            return;
        break;
      case EVP_PKEY_DSA:
        DSA_get0_key(ptr, &pubkey, NULL);
        if (pubkey)
            return;
        break;
      case EVP_PKEY_DH:
        DH_get0_key(ptr, &pubkey, NULL);
        if (pubkey)
            return;
        break;
#if !defined(OPENSSL_NO_EC)
      case EVP_PKEY_EC:
        if (EC_KEY_get0_public_key(ptr))
            return;
        break;
#endif
      default:
        /* unsupported type; assuming ok */
        return;
    }
    ossl_raise(ePKeyError, "public key missing");
}

EVP_PKEY *
GetPKeyPtr(VALUE obj)
{
    EVP_PKEY *pkey;

    SafeGetPKey(obj, pkey);

    return pkey;
}

EVP_PKEY *
GetPrivPKeyPtr(VALUE obj)
{
    EVP_PKEY *pkey;
	
    if (rb_funcall(obj, id_private_q, 0, NULL) != Qtrue) {
	ossl_raise(rb_eArgError, "Private key is needed.");
    }
    SafeGetPKey(obj, pkey);

    return pkey;
}

EVP_PKEY *
DupPKeyPtr(VALUE obj)
{
    EVP_PKEY *pkey;
	
    SafeGetPKey(obj, pkey);
    EVP_PKEY_up_ref(pkey);

    return pkey;
}

EVP_PKEY *
DupPrivPKeyPtr(VALUE obj)
{
    EVP_PKEY *pkey;
	
    if (rb_funcall(obj, id_private_q, 0, NULL) != Qtrue) {
	ossl_raise(rb_eArgError, "Private key is needed.");
    }
    SafeGetPKey(obj, pkey);
    EVP_PKEY_up_ref(pkey);

    return pkey;
}

/*
 * Private
 */
static VALUE
ossl_pkey_alloc(VALUE klass)
{
    EVP_PKEY *pkey;
    VALUE obj;

    if (!(pkey = EVP_PKEY_new())) {
	ossl_raise(ePKeyError, NULL);
    }
    WrapPKey(klass, obj, pkey);

    return obj;
}

static VALUE
ossl_pkey_initialize(VALUE self)
{
    if (rb_obj_is_instance_of(self, cPKey)) {
	ossl_raise(rb_eNotImpError, "OpenSSL::PKey::PKey is an abstract class.");
    }
    return self;
}

static VALUE
ossl_pkey_sign(VALUE self, VALUE digest, VALUE data)
{
    EVP_PKEY *pkey;
    const EVP_MD *md;
    EVP_MD_CTX *ctx;
    int buf_len;
    VALUE str;
    int result;

    pkey = GetPrivPKeyPtr(self);
    md = GetDigestPtr(digest);
    StringValue(data);
    str = rb_str_new(0, EVP_PKEY_size(pkey));

    ctx = EVP_MD_CTX_new();
    if (!ctx)
       ossl_raise(ePKeyError, "EVP_MD_CTX_new");
    if (!EVP_SignInit_ex(ctx, md, NULL)) {
       EVP_MD_CTX_free(ctx);
       ossl_raise(ePKeyError, "EVP_SignInit_ex");
    }
    if (!EVP_SignUpdate(ctx, RSTRING_PTR(data), RSTRING_LEN(data))) {
       EVP_MD_CTX_free(ctx);
       ossl_raise(ePKeyError, "EVP_SignUpdate");
    }
    result = EVP_SignFinal(ctx, (unsigned char *)RSTRING_PTR(str), &buf_len, pkey);
    EVP_MD_CTX_free(ctx);
    if (!result)
       ossl_raise(ePKeyError, "EVP_SignFinal");

    rb_str_set_len(str, buf_len);

    return str;
}

static VALUE
ossl_pkey_verify(VALUE self, VALUE digest, VALUE sig, VALUE data)
{
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    int result;

    GetPKey(self, pkey);
    ossl_pkey_check_public_key(pkey);
    StringValue(sig);
    StringValue(data);

    ctx = EVP_MD_CTX_new();
    if (!ctx)
       ossl_raise(ePKeyError, "EVP_MD_CTX_new");
    EVP_VerifyInit(ctx, GetDigestPtr(digest));
    EVP_VerifyUpdate(ctx, RSTRING_PTR(data), RSTRING_LEN(data));
    result = EVP_VerifyFinal(ctx, (unsigned char *)RSTRING_PTR(sig), RSTRING_LEN(sig), pkey);
    EVP_MD_CTX_free(ctx);
    switch (result) {
    case 0:
	return Qfalse;
    case 1:
	return Qtrue;
    default:
	ossl_raise(ePKeyError, NULL);
    }
    return Qnil; /* dummy */
}

/*
 * INIT
 */
void
Init_ossl_pkey()
{
#if 0 /* let rdoc know about mOSSL */
    mOSSL = rb_define_module("OpenSSL");
#endif
        
    mPKey = rb_define_module_under(mOSSL, "PKey");
	
    ePKeyError = rb_define_class_under(mPKey, "PKeyError", eOSSLError);

    cPKey = rb_define_class_under(mPKey, "PKey", rb_cObject);
	
    rb_define_alloc_func(cPKey, ossl_pkey_alloc);
    rb_define_method(cPKey, "initialize", ossl_pkey_initialize, 0);

    rb_define_method(cPKey, "sign", ossl_pkey_sign, 2);
    rb_define_method(cPKey, "verify", ossl_pkey_verify, 3);
	
    id_private_q = rb_intern("private?");
	
    /*
     * INIT rsa, dsa, dh, ec
     */
    Init_ossl_rsa();
    Init_ossl_dsa();
    Init_ossl_dh();
    Init_ossl_ec();
}

