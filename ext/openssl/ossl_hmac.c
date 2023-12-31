/*
 * $Id: ossl_hmac.c 28004 2010-05-24 23:58:49Z shyouhei $
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#if !defined(OPENSSL_NO_HMAC)

#include "ossl.h"

#define NewHMAC(klass) \
    Data_Wrap_Struct((klass), 0, &ossl_hmac_free, 0)
#define GetHMAC(obj, ctx) do { \
    Data_Get_Struct(obj, HMAC_CTX, ctx); \
    if (!ctx) { \
	ossl_raise(rb_eRuntimeError, "HMAC wasn't initialized"); \
    } \
} while (0)
#define SafeGetHMAC(obj, ctx) do { \
    OSSL_Check_Kind(obj, cHMAC); \
    GetHMAC(obj, ctx); \
} while (0)

/*
 * Classes
 */
VALUE cHMAC;
VALUE eHMACError;

/*
 * Public
 */

/*
 * Private
 */
static void
ossl_hmac_free(HMAC_CTX *ctx)
{
    HMAC_CTX_free(ctx);
}

static VALUE
ossl_hmac_alloc(VALUE klass)
{
    HMAC_CTX *ctx;
    VALUE obj;

    obj = NewHMAC(klass);
    ctx = HMAC_CTX_new();
    if (!ctx)
       ossl_raise(eHMACError, NULL);
    DATA_PTR(obj) = ctx;
	
    return obj;
}


/*
 *  call-seq:
 *     HMAC.new(key, digest) -> hmac
 *
 */
static VALUE
ossl_hmac_initialize(VALUE self, VALUE key, VALUE digest)
{
    HMAC_CTX *ctx;

    StringValue(key);
    GetHMAC(self, ctx);
    HMAC_Init_ex(ctx, RSTRING_PTR(key), RSTRING_LEN(key),
		 GetDigestPtr(digest), NULL);

    return self;
}

static VALUE
ossl_hmac_copy(VALUE self, VALUE other)
{
    HMAC_CTX *ctx1, *ctx2;
    
    rb_check_frozen(self);
    if (self == other) return self;

    GetHMAC(self, ctx1);
    SafeGetHMAC(other, ctx2);

    HMAC_CTX_copy(ctx1, ctx2);
    return self;
}

/*
 *  call-seq:
 *     hmac.update(string) -> self
 *
 */
static VALUE
ossl_hmac_update(VALUE self, VALUE data)
{
    HMAC_CTX *ctx;

    StringValue(data);
    GetHMAC(self, ctx);
    HMAC_Update(ctx, RSTRING_PTR(data), RSTRING_LEN(data));

    return self;
}

static void
hmac_final(HMAC_CTX *ctx, char *buf, int *buf_len)
{
    HMAC_CTX *final;

    final = HMAC_CTX_new();
    if (!final)
        ossl_raise(eHMACError, "HMAC_CTX_new");

    if (!HMAC_CTX_copy(final, ctx)) {
       HMAC_CTX_free(final);
       ossl_raise(eHMACError, "HMAC_CTX_copy");
    }

    HMAC_Final(final, buf, buf_len);
    HMAC_CTX_free(final);
}

/*
 *  call-seq:
 *     hmac.digest -> aString
 *
 */
static VALUE
ossl_hmac_digest(VALUE self)
{
    HMAC_CTX *ctx;
    int buf_len;
    VALUE ret;
	
    GetHMAC(self, ctx);
    ret = rb_str_new(NULL, EVP_MAX_MD_SIZE);
    hmac_final(ctx, (unsigned char *)RSTRING_PTR(ret), &buf_len);
    assert(buf_len <= EVP_MAX_MD_SIZE);
    rb_str_set_len(ret, buf_len);

    return ret;
}

/*
 *  call-seq:
 *     hmac.hexdigest -> aString
 *
 */
static VALUE
ossl_hmac_hexdigest(VALUE self)
{
    HMAC_CTX *ctx;
    unsigned char buf[EVP_MAX_MD_SIZE];
    int buf_len;
    VALUE ret;
	
    GetHMAC(self, ctx);
    hmac_final(ctx, buf, &buf_len);
    ret = rb_str_new(NULL, buf_len * 2);
    ossl_bin2hex(buf, RSTRING_PTR(ret), buf_len);

    return ret;
}

/*
 *  call-seq:
 *     hmac.reset -> self
 *
 */
static VALUE
ossl_hmac_reset(VALUE self)
{
    HMAC_CTX *ctx;

    GetHMAC(self, ctx);
    HMAC_Init_ex(ctx, NULL, 0, NULL, NULL);

    return self;
}

/*
 *  call-seq:
 *     HMAC.digest(digest, key, data) -> aString
 *
 */
static VALUE
ossl_hmac_s_digest(VALUE klass, VALUE digest, VALUE key, VALUE data)
{
    char *buf;
    int buf_len;
	
    StringValue(key);
    StringValue(data);
    buf = HMAC(GetDigestPtr(digest), RSTRING_PTR(key), RSTRING_LEN(key),
	       RSTRING_PTR(data), RSTRING_LEN(data), NULL, &buf_len);

    return rb_str_new(buf, buf_len);
}

/*
 *  call-seq:
 *     HMAC.digest(digest, key, data) -> aString
 *
 */
static VALUE
ossl_hmac_s_hexdigest(VALUE klass, VALUE digest, VALUE key, VALUE data)
{
    char *buf, *hexbuf;
    int buf_len;
    VALUE hexdigest;

    StringValue(key);
    StringValue(data);
	
    buf = HMAC(GetDigestPtr(digest), RSTRING_PTR(key), RSTRING_LEN(key),
	       RSTRING_PTR(data), RSTRING_LEN(data), NULL, &buf_len);
    if (string2hex(buf, buf_len, &hexbuf, NULL) != 2 * buf_len) {
	ossl_raise(eHMACError, "Cannot convert buf to hexbuf");
    }
    hexdigest = ossl_buf2str(hexbuf, 2 * buf_len);

    return hexdigest;
}

/*
 * INIT
 */
void
Init_ossl_hmac()
{
#if 0 /* let rdoc know about mOSSL */
    mOSSL = rb_define_module("OpenSSL");
#endif

    eHMACError = rb_define_class_under(mOSSL, "HMACError", eOSSLError);
	
    cHMAC = rb_define_class_under(mOSSL, "HMAC", rb_cObject);

    rb_define_alloc_func(cHMAC, ossl_hmac_alloc);
    rb_define_singleton_method(cHMAC, "digest", ossl_hmac_s_digest, 3);
    rb_define_singleton_method(cHMAC, "hexdigest", ossl_hmac_s_hexdigest, 3);
    
    rb_define_method(cHMAC, "initialize", ossl_hmac_initialize, 2);
    rb_define_copy_func(cHMAC, ossl_hmac_copy);

    rb_define_method(cHMAC, "reset", ossl_hmac_reset, 0);
    rb_define_method(cHMAC, "update", ossl_hmac_update, 1);
    rb_define_alias(cHMAC, "<<", "update");
    rb_define_method(cHMAC, "digest", ossl_hmac_digest, 0);
    rb_define_method(cHMAC, "hexdigest", ossl_hmac_hexdigest, 0);
    rb_define_alias(cHMAC, "inspect", "hexdigest");
    rb_define_alias(cHMAC, "to_s", "hexdigest");
}

#else /* NO_HMAC */
#  warning >>> OpenSSL is compiled without HMAC support <<<
void
Init_ossl_hmac()
{
    rb_warning("HMAC will NOT be avaible: OpenSSL is compiled without HMAC.");
}
#endif /* NO_HMAC */
