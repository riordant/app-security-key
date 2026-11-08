/* Retained Ledger SIV/CMAC code, real AES blocks supplied by OpenSSL in tests. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "lcx_aes_siv.h"
#include "lcx_cmac.h"
#include "cx_ram.h"
#include "crypto_vectors.h"

void test_fill_workspace(unsigned char value);
void test_fail_after(int blocks);
size_t test_wipe_calls(void);

static void setup(cx_aes_siv_context_t *siv, cx_cipher_context_t *cipher,
                  cipher_key_t *key, const uint8_t *raw, size_t len) {
    memset(siv,0xa5,sizeof(*siv)); memset(cipher,0xa5,sizeof(*cipher)); memset(key,0xa5,sizeof(*key));
    siv->cipher_ctx=cipher;
    siv->cipher_type=len==32?CX_CIPHER_AES_128:len==48?CX_CIPHER_AES_192:CX_CIPHER_AES_256;
    assert(cx_aes_siv_init(siv)==CX_OK); cipher->cipher_key=key;
    assert(cx_aes_siv_set_key(siv,raw,len*8)==CX_OK);
}
static void zero(const void *value,size_t len) {
    const uint8_t *p=value; for (size_t i=0;i<len;i++) assert(p[i]==0);
}

static void vectors(void) {
    for (size_t i=0;i<SIV_VECTOR_COUNT;i++) {
        const struct siv_vector *v=&siv_vectors[i];
        cx_aes_siv_context_t s; cx_cipher_context_t c; cipher_key_t k;
        uint8_t output[1100],tag[16],bad[16];
        const uint8_t *ad=v->present?v->ad:NULL;
        setup(&s,&c,&k,v->key,v->keylen);
        assert(cx_aes_siv_encrypt(&s,v->plain,v->len,ad,v->adlen,output,tag)==CX_OK);
        assert(memcmp(output,v->cipher,v->len)==0 && memcmp(tag,v->tag,16)==0);
        zero(&G_cx.cmac,sizeof(G_cx.cmac));
        assert(cx_aes_siv_decrypt(&s,v->cipher,v->len,ad,v->adlen,output,tag)==CX_OK);
        assert(memcmp(output,v->plain,v->len)==0);
        memcpy(output,v->plain,v->len);
        assert(cx_aes_siv_encrypt(&s,output,v->len,ad,v->adlen,output,tag)==CX_OK);
        assert(memcmp(output,v->cipher,v->len)==0);
        assert(cx_aes_siv_decrypt(&s,output,v->len,ad,v->adlen,output,tag)==CX_OK);
        assert(memcmp(output,v->plain,v->len)==0);
        if (i%23==0) for (size_t bit=0;bit<128;bit++) {
            memcpy(bad,tag,16); bad[bit/8]^=1u<<(bit%8); memset(output,0xa5,sizeof(output));
            assert(cx_aes_siv_decrypt(&s,v->cipher,v->len,ad,v->adlen,output,bad)!=CX_OK);
            zero(output,v->len); zero(&G_cx.cmac,sizeof(G_cx.cmac));
        }
        if (i%23==0 && v->len) {
            memcpy(output,v->cipher,v->len); output[v->len/2]^=0x80;
            assert(cx_aes_siv_decrypt(&s,output,v->len,ad,v->adlen,output,tag)!=CX_OK);
            zero(output,v->len);
        }
        if (i%23==0 && v->adlen) {
            uint8_t bad_ad[64]; memcpy(bad_ad,v->ad,v->adlen); bad_ad[0]^=1;
            assert(cx_aes_siv_decrypt(&s,v->cipher,v->len,bad_ad,v->adlen,output,tag)!=CX_OK);
            zero(output,v->len);
        }
    }
}

static void rfc2(void) {
    cx_aes_siv_context_t s; cx_cipher_context_t c; cipher_key_t k;
    uint8_t output[sizeof(rfc2_plain)],tag[16];
    setup(&s,&c,&k,rfc2_key,sizeof(rfc2_key));
    assert(cx_aes_siv_start(&s,CX_ENCRYPT,NULL,0)==CX_OK);
    assert(cx_aes_siv_update_aad(&s,rfc2_ad1,sizeof(rfc2_ad1))==CX_OK);
    assert(cx_aes_siv_update_aad(&s,rfc2_ad2,sizeof(rfc2_ad2))==CX_OK);
    assert(cx_aes_siv_update_aad(&s,rfc2_nonce,sizeof(rfc2_nonce))==CX_OK);
    assert(cx_aes_siv_finish(&s,rfc2_plain,sizeof(rfc2_plain),tag)==CX_OK);
    assert(cx_aes_siv_update(&s,rfc2_plain,output,sizeof(output))==CX_OK);
    assert(memcmp(output,rfc2_cipher,sizeof(output))==0 && memcmp(tag,rfc2_tag,16)==0);
    assert(cx_aes_siv_start(&s,CX_DECRYPT,tag,16)==CX_OK);
    assert(cx_aes_siv_update(&s,output,output,sizeof(output))==CX_OK);
    assert(cx_aes_siv_update_aad(&s,rfc2_ad1,sizeof(rfc2_ad1))==CX_OK);
    assert(cx_aes_siv_update_aad(&s,rfc2_ad2,sizeof(rfc2_ad2))==CX_OK);
    assert(cx_aes_siv_update_aad(&s,rfc2_nonce,sizeof(rfc2_nonce))==CX_OK);
    assert(cx_aes_siv_finish(&s,output,sizeof(output),tag)==CX_OK);
    assert(memcmp(output,rfc2_plain,sizeof(output))==0);
}

static void cmac(void) {
    for(size_t i=0;i<CMAC_VECTOR_COUNT;i++) {
        const struct cmac_vector *v=&cmac_vectors[i];
        uint8_t tag[16];
        cx_cipher_id_t type=v->keylen==16?CX_CIPHER_AES_128:v->keylen==24?CX_CIPHER_AES_192:CX_CIPHER_AES_256;
        assert(cx_cmac(type,v->key,v->keylen*8,v->plain,v->len,tag)==CX_OK);
        assert(memcmp(tag,v->tag,16)==0);
        for(size_t split=0;split<=v->len;split++) {
            cx_cipher_context_t c; cipher_key_t k;
            assert(cx_cipher_init(&c)==CX_OK); c.cipher_key=&k;
            assert(cx_cipher_setup(&c,type,CX_CHAIN_ECB)==CX_OK);
            assert(cx_cmac_start(&c,v->key,v->keylen*8)==CX_OK);
            assert(cx_cmac_update(&c,v->plain,split)==CX_OK);
            assert(cx_cmac_update(&c,v->plain+split,v->len-split)==CX_OK);
            assert(cx_cmac_finish(&c,tag)==CX_OK);
            assert(memcmp(tag,v->tag,16)==0); zero(&G_cx.cmac,sizeof(G_cx.cmac));
        }
    }
}

static void invalid_and_faults(void) {
    cx_aes_siv_context_t s; cx_cipher_context_t c; cipher_key_t k;
    uint8_t key[64]={0},data[64]={0},out[80],tag[16]={0};
    setup(&s,&c,&k,key,32);
    assert(cx_aes_siv_init(NULL)!=CX_OK);
    assert(cx_aes_siv_set_key(NULL,key,256)!=CX_OK);
    for (size_t len=0;len<80;len++) if(len!=16)
        assert(cx_aes_siv_start(&s,CX_DECRYPT,tag,len)!=CX_OK);
    assert(cx_aes_siv_start(&s,CX_DECRYPT,NULL,16)!=CX_OK);
    for(size_t bits=0;bits<600;bits++) if(bits!=256)
        assert(cx_aes_siv_set_key(&s,key,bits)!=CX_OK);
    assert(cx_aes_siv_encrypt(&s,NULL,1,NULL,0,out,tag)!=CX_OK);
    assert(cx_aes_siv_encrypt(&s,data,16,NULL,1,out,tag)!=CX_OK);
    assert(cx_aes_siv_encrypt(&s,data,SIZE_MAX,NULL,0,out,tag)!=CX_OK);
    assert(cx_aes_siv_encrypt(&s,data,16,NULL,0,data+1,tag)!=CX_OK);
    assert(cx_aes_siv_encrypt(&s,data,16,NULL,0,out,data)!=CX_OK);
    assert(cx_aes_siv_encrypt(&s,data,16,out,16,out,tag)!=CX_OK);
    assert(cx_aes_siv_encrypt(&s,NULL,0,NULL,0,NULL,tag)==CX_OK);
    assert(cx_aes_siv_decrypt(&s,NULL,0,NULL,0,NULL,tag)==CX_OK);
    assert(cx_cmac_update(NULL,data,1)!=CX_OK && cx_cmac_finish(NULL,tag)!=CX_OK);
    uint8_t doubled[16]={0x80};
    assert(cx_cmac_shift_and_xor(doubled,doubled,16)==CX_OK);
    for(int i=0;i<15;i++)assert(doubled[i]==0); assert(doubled[15]==0x87);
    assert(cx_cipher_setup(&c,CX_CIPHER_AES_128,CX_CHAIN_ECB)==CX_OK);
    c.unprocessed_len=15; size_t capacity=8;
    assert(cx_cipher_update(&c,data,1,out,&capacity)!=CX_OK);
    c.unprocessed_len=SIZE_MAX; capacity=sizeof(out);
    assert(cx_cipher_update(&c,data,1,out,&capacity)!=CX_OK);
    for(int failure=0;failure<40;failure++) {
        setup(&s,&c,&k,key,32); test_fill_workspace(0xa5); memset(out,0xa5,sizeof(out));
        test_fail_after(failure);
        cx_err_t status=cx_aes_siv_encrypt(&s,data,sizeof(data),data,32,out,tag);
        test_fail_after(-1);
        if(status!=CX_OK) { zero(out,sizeof(data)); zero(tag,16); }
        zero(&G_cx.cmac,sizeof(G_cx.cmac));
    }
    setup(&s,&c,&k,key,32);
    assert(cx_aes_siv_encrypt(&s,data,sizeof(data),data,32,out,tag)==CX_OK);
    uint8_t ciphertext[64]; memcpy(ciphertext,out,64);
    for(int failure=0;failure<40;failure++) {
        setup(&s,&c,&k,key,32); test_fill_workspace(0xa5); memset(out,0xa5,sizeof(out));
        test_fail_after(failure);
        cx_err_t status=cx_aes_siv_decrypt(&s,ciphertext,64,data,32,out,tag);
        test_fail_after(-1);
        if(status!=CX_OK) zero(out,64);
        zero(&G_cx.cmac,sizeof(G_cx.cmac));
    }
    assert(test_wipe_calls()>100);
}

static void helper_boundaries(void) {
    // Exercise every carry position; the 0x80-at-byte-zero case alone does not
    // detect a carry read after the same byte has been overwritten in place.
    for (unsigned bit=0;bit<128;bit++) {
        uint8_t input[16]={0}, expected[16]={0}, actual[16];
        input[bit/8]=(uint8_t)(1u << (7-bit%8));
        if(bit==0) expected[15]=0x87;
        else expected[(bit-1)/8]=(uint8_t)(1u << (7-(bit-1)%8));
        memcpy(actual,input,sizeof(actual));
        assert(cx_cmac_shift_and_xor(actual,actual,16)==CX_OK);
        assert(memcmp(actual,expected,sizeof(actual))==0);
    }
    // A decrypt update must retain a complete final block for finish(), even
    // when that block arrived over multiple calls. No output capacity is needed
    // until another input byte makes it safe to release the retained block.
    for(size_t split=0;split<=16;split++) {
        cx_cipher_context_t c; cipher_key_t k;
        uint8_t key[16]={0}, data[17]={0}, out[17]; size_t capacity=0;
        assert(cx_cipher_init(&c)==CX_OK); c.cipher_key=&k;
        assert(cx_cipher_setup(&c,CX_CIPHER_AES_128,CX_CHAIN_ECB)==CX_OK);
        assert(cx_cipher_setkey(&c,key,128,CX_DECRYPT)==CX_OK);
        memset(out,0xa5,sizeof(out));
        assert(cx_cipher_update(&c,data,split,out,&capacity)==CX_OK && capacity==0);
        assert(cx_cipher_update(&c,data+split,16-split,out,&capacity)==CX_OK && capacity==0);
        for(size_t i=0;i<sizeof(out);i++) assert(out[i]==0xa5);
        capacity=15;
        assert(cx_cipher_update(&c,data+16,1,out,&capacity)!=CX_OK);
        capacity=16;
        assert(cx_cipher_update(&c,data+16,1,out,&capacity)==CX_OK && capacity==16);
        assert(out[16]==0xa5 && c.unprocessed_len==1);
    }
}

int main(void) {
    vectors(); rfc2(); cmac(); invalid_and_faults(); helper_boundaries();
    printf("crypto: %u SIV oracle vectors plus RFC 5297 A.2, %u CMAC vectors with every split, tampering, invalid inputs and AES faults passed\n",SIV_VECTOR_COUNT,CMAC_VECTOR_COUNT);
}
