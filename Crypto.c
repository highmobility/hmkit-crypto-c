/*
The MIT License

Copyright (c) 2014- High-Mobility GmbH (https://high-mobility.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "Crypto.h"
#include "hmkit_core_config.h"

// C-includes
#include <math.h>
#include <stdio.h>
#include <string.h>

// Crypto-includes
#include <openssl/aes.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define CRYPTO_PER_BLOCK_SIZE 64

//#define DYNAMIC_MEM_DATA

//PROTOTYPES
uint32_t p_create_sha256(uint8_t *message, uint8_t size, uint8_t *hash_out, bool padded);
uint32_t p_free_keys_variables(EC_KEY *a, BIGNUM *b, EC_GROUP *c, EC_POINT *d, BN_CTX *e);
void p_extract_private_key(EC_KEY *key, uint8_t *private_key);
void p_extract_public_key(EC_KEY *key, uint8_t *public_key);
uint32_t p_free_signature_variables(EC_KEY *a, BIGNUM *b, ECDSA_SIG *c);
uint32_t p_free_verify_variables(EC_KEY *a, BIGNUM *b, BIGNUM *c, ECDSA_SIG *d, EC_GROUP *g, EC_POINT *h);
uint32_t p_free_hmac_variables(HMAC_CTX *a);
uint32_t p_free_dh_variables(EC_KEY *a, BIGNUM *b, BIGNUM *c, BIGNUM *d, EC_POINT *e, BN_CTX *f);
void get_roundoff_64(uint16_t size, uint16_t *out_size);
void p_fill_to_roundedSize(uint8_t *data, uint16_t size, uint16_t rounded_size,uint8_t *buffer);


void p_fill_to_roundedSize(uint8_t *data, uint16_t size, uint16_t rounded_size,uint8_t *buffer) 
{
	memset(buffer, 0x00, rounded_size);
	memcpy(buffer, data, size);
}

uint32_t p_create_sha256(uint8_t *message, uint8_t size, uint8_t *hash_out, bool padded)
{
	uint16_t roundedSize = 0;
	uint8_t hash[SHA256_DIGEST_LENGTH];

    #ifdef DYNAMIC_MEM_DATA
        uint8_t *data = (uint8_t *)malloc(MAX_COMMAND_SIZE);
    #else
        uint8_t data[MAX_COMMAND_SIZE];
    #endif

	// Pad the message if required
    if (padded) {
        get_roundoff_64(size, &roundedSize);
    }
    else {
        roundedSize = size;
    }

    p_fill_to_roundedSize(message, size, roundedSize, data);

    // Create the SHA256
	if (NULL == SHA256((unsigned char *)data, roundedSize, (unsigned char *)&hash)) {
        #ifdef DYNAMIC_MEM_DATA
            free(data);
        #endif

		return 1;
	}

	// Output
	memcpy(hash_out, hash, SHA256_DIGEST_LENGTH);

    #ifdef DYNAMIC_MEM_DATA
        free(data);
    #endif

	return 0;
}

void get_roundoff_64(uint16_t size, uint16_t *out_size)
{
	uint8_t mod = 0;
	uint16_t div = 0;

	if(size > CRYPTO_PER_BLOCK_SIZE)
	{
		mod = size % CRYPTO_PER_BLOCK_SIZE;
	    div = size/CRYPTO_PER_BLOCK_SIZE;

		if(mod)
		{
			*out_size =  CRYPTO_PER_BLOCK_SIZE * (div + 1);
		}
		else
		{
			*out_size = CRYPTO_PER_BLOCK_SIZE * div;
		}

	}
	else
	{ // minimum block size
		*out_size = CRYPTO_PER_BLOCK_SIZE;
	}

	//fprintf(stderr, "DEBUG: get_roundoff_64, inp size = %d, out size = %d, mod = %d, div = %d\n", size, *out_size, mod, div);

}


// Keys
uint32_t p_free_keys_variables(EC_KEY *a, BIGNUM *b, EC_GROUP *c, EC_POINT *d, BN_CTX *e) {
    CRUNUSED(c);
    CRUNUSED(d);
    CRUNUSED(e);

    EC_KEY_free(a);
    BN_free(b);

    return 1;
}

void p_extract_private_key(EC_KEY *key, uint8_t *private_key) {
    const BIGNUM *bnKey = EC_KEY_get0_private_key(key);
    int size = BN_num_bytes(bnKey);
    uint8_t private[100];
    uint8_t tempPrivate[32];

    BN_bn2bin(bnKey, private);

    memset(tempPrivate, 0x00, 32);
    memcpy((tempPrivate + (32 - size)), private, size);

    // Output
    memcpy(private_key, tempPrivate, 32);
}

void p_extract_public_key(EC_KEY *key, uint8_t *public_key) {
    const EC_GROUP *group   = EC_KEY_get0_group(key);
    const EC_POINT *point   = EC_KEY_get0_public_key(key);

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *pub = BN_new();
    uint8_t public[100];

    EC_POINT_point2bn(group, point, POINT_CONVERSION_UNCOMPRESSED, pub, ctx);
    BN_bn2bin(pub, public);

    // Output
    memcpy(public_key, public + 1, 64);

    // Cleanup
    BN_CTX_free(ctx);
}

uint32_t hm_crypto_openssl_create_keys(uint8_t *private_key, uint8_t *public_key, bool create_both) {
    if (create_both) {
        EC_KEY *key;
        uint8_t private[32];
        uint8_t public[64];

        // This is like the 'guard' statements in swift
        if (NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) return p_free_keys_variables(key, NULL, NULL, NULL, NULL);
        if (1 != EC_KEY_generate_key(key))                                  return p_free_keys_variables(key, NULL, NULL, NULL, NULL);
        if (1 != EC_KEY_check_key(key))                                     return p_free_keys_variables(key, NULL, NULL, NULL, NULL);

        p_extract_private_key(key, private);
        p_extract_public_key(key, public);

        // Output
        memcpy(private_key, private, 32);
        memcpy(public_key, public, 64);

        // Cleanup
        p_free_keys_variables(key, NULL, NULL, NULL, NULL);
    }
    else {
        EC_KEY *key = NULL;
        BIGNUM *bn = NULL;
        EC_GROUP *group = NULL;
        EC_POINT *point = NULL;
        BN_CTX *ctx = NULL;
        uint8_t public[100];

        if (NULL == (group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1))) return p_free_keys_variables(key, bn, group, point, ctx);
        if (NULL == (bn = BN_new()))                                            return p_free_keys_variables(key, bn, group, point, ctx);

        BN_bin2bn(private_key, 32, bn);

        if (NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))     return p_free_keys_variables(key, bn, group, point, ctx);
        if (NULL == (point = EC_POINT_new(group)))                              return p_free_keys_variables(key, bn, group, point, ctx);
        if (NULL == (ctx = BN_CTX_new()))                                       return p_free_keys_variables(key, bn, group, point, ctx);

        if (1 != EC_KEY_set_private_key(key, bn))                               return p_free_keys_variables(key, bn, group, point, ctx);
        if (1 != EC_KEY_generate_key(key))                                      return p_free_keys_variables(key, bn, group, point, ctx);
        if (1 != EC_KEY_check_key(key))                                         return p_free_keys_variables(key, bn, group, point, ctx);
        if (1 != EC_POINT_mul(group, point, bn, NULL, NULL, NULL))              return p_free_keys_variables(key, bn, group, point, ctx);

        EC_POINT_point2bn(group, point, POINT_CONVERSION_UNCOMPRESSED, bn, ctx);
        BN_bn2bin(bn, public);

        // Output
        memcpy(public_key, public + 1, 64);

        // Cleanup
        p_free_keys_variables(key, bn, group, point, ctx);
    }

    return 0;
}


// Signature
uint32_t p_free_signature_variables(EC_KEY *a, BIGNUM *b, ECDSA_SIG *c) {
    EC_KEY_free(a);
    BN_clear_free(b);
    ECDSA_SIG_free(c);

    return 1;
}

uint32_t p_create_signature(uint8_t *message, uint8_t size, uint8_t *private_key, uint8_t *signature, bool padded) {
    EC_KEY *key = NULL;
    BIGNUM *bn = NULL;
    ECDSA_SIG *sig = NULL;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint8_t rBin[32];
    uint8_t sBin[32];

    // Variable creation
    if (NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) return p_free_signature_variables(key, bn, sig);
    if (NULL == (bn = BN_new()))                                        return p_free_signature_variables(key, bn, sig);
    if (NULL == (sig = ECDSA_SIG_new()))                                return p_free_signature_variables(key, bn, sig);

    // Key calculations
    if (NULL == BN_bin2bn(private_key, 32, bn))                         return p_free_signature_variables(key, bn, sig);
    if (1 != EC_KEY_set_private_key(key, bn))                           return p_free_signature_variables(key, bn, sig);

    // Signature calculations
    if (0 != p_create_sha256(message, size, hash, padded))              return p_free_signature_variables(key, bn, sig);
    if (NULL == (sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, key))) return p_free_signature_variables(key, bn, sig);

    const BIGNUM *sig_r, *sig_s;
    ECDSA_SIG_get0(sig, &sig_r, &sig_s);

    // Big number calculations
    if (0 == BN_bn2bin(sig_r, rBin))                                   return p_free_signature_variables(key, bn, sig);
    if (0 == BN_bn2bin(sig_s, sBin))                                   return p_free_signature_variables(key, bn, sig);

    // Sizes of the vectors
    int rSize = (int)(ceil((double)(BN_num_bits(sig_r)) / 8.0));
    int sSize = (int)(ceil((double)(BN_num_bits(sig_s)) / 8.0));
    uint8_t tempSignature[64];

    // Secret handling
    memset(tempSignature, 0x00, 64);
    memcpy((tempSignature + (32 - rSize)),      rBin, rSize);
    memcpy((tempSignature + 32 + (32 - sSize)), sBin, sSize);

    // Output
    memcpy(signature, tempSignature, 64);

    // Cleanup
    p_free_signature_variables(key, bn, sig);

    return 0;
}

uint32_t hm_crypto_openssl_signature(uint8_t *message, uint8_t size, uint8_t *private_key, uint8_t *signature) {
    EC_KEY *key = NULL;
    BIGNUM *bn = NULL;
    ECDSA_SIG *sig = NULL;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint8_t rBin[32];
    uint8_t sBin[32];

    // Variable creation
    if (NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) return p_free_signature_variables(key, bn, sig);
    if (NULL == (bn = BN_new()))                                        return p_free_signature_variables(key, bn, sig);
    if (NULL == (sig = ECDSA_SIG_new()))                                return p_free_signature_variables(key, bn, sig);

    // Key calculations
    if (NULL == BN_bin2bn(private_key, 32, bn))                         return p_free_signature_variables(key, bn, sig);
    if (1 != EC_KEY_set_private_key(key, bn))                           return p_free_signature_variables(key, bn, sig);

    // Signature calculations
    if (0 != p_create_sha256(message, size, hash, true))                      return p_free_signature_variables(key, bn, sig);
    if (NULL == (sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, key))) return p_free_signature_variables(key, bn, sig);

    const BIGNUM *sig_r, *sig_s;
    ECDSA_SIG_get0(sig, &sig_r, &sig_s);

    // Big number calculations
    if (0 == BN_bn2bin(sig_r, rBin))                                   return p_free_signature_variables(key, bn, sig);
    if (0 == BN_bn2bin(sig_s, sBin))                                   return p_free_signature_variables(key, bn, sig);

    // Sizes of the vectors
    int rSize = (int)(ceil((double)(BN_num_bits(sig_r)) / 8.0));
    int sSize = (int)(ceil((double)(BN_num_bits(sig_s)) / 8.0));
    uint8_t tempSignature[64];

    // Secret handling
    memset(tempSignature, 0x00, 64);
    memcpy((tempSignature + (32 - rSize)),      rBin, rSize);
    memcpy((tempSignature + 32 + (32 - sSize)), sBin, sSize);

    // Output
    memcpy(signature, tempSignature, 64);

    // Cleanup
    p_free_signature_variables(key, bn, sig);

    return 0;
}


// Verify signature
uint32_t p_free_verify_variables(EC_KEY *a, BIGNUM *b, BIGNUM *c, ECDSA_SIG *d, EC_GROUP *g, EC_POINT *h) {
    EC_KEY_free(a);
    BN_clear_free(b);
    BN_clear_free(c);
    ECDSA_SIG_free(d);
    EC_GROUP_clear_free(g);
    EC_POINT_clear_free(h);

    return 1;
}

uint32_t hm_crypto_openssl_verify(uint8_t *message, uint8_t size, uint8_t *public_key, uint8_t *signature) {
    EC_KEY *key = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *pub_x = NULL;
    BIGNUM *pub_y = NULL;
    ECDSA_SIG *sig = NULL;
    BIGNUM *sig_r = NULL;
    BIGNUM *sig_s = NULL;
    uint8_t verified = 0;
    uint8_t hash[SHA256_DIGEST_LENGTH];

    // Variable creation
    if (NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))     return 1;
    if (NULL == (pub_x = BN_new()))                                         return p_free_verify_variables(key, pub_x, pub_y, sig, group, point);
    if (NULL == (pub_y = BN_new()))                                         return p_free_verify_variables(key, pub_x, pub_y, sig, group, point);
    if (NULL == (group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1))) return p_free_verify_variables(key, pub_x, pub_y, sig, group, point);
    if (NULL == (point = EC_POINT_new(group)))                              return p_free_verify_variables(key, pub_x, pub_y, sig, group, point);

    // Big number conversion
    BN_bin2bn(public_key,       32, pub_x);
    BN_bin2bn(public_key + 32,  32, pub_y);

    // Crypto calculations
    if (1 != EC_POINT_set_affine_coordinates_GFp(group, point, pub_x, pub_y, NULL))
                                                                            return p_free_verify_variables(key, pub_x, pub_y, sig, group, point);
    if (1 != EC_KEY_set_public_key(key, point))                             return p_free_verify_variables(key, pub_x, pub_y, sig, group, point);
    if (1 != EC_KEY_check_key(key))                                         return p_free_verify_variables(key, pub_x, pub_y, sig, group, point);

    // Variable creation
    if (NULL == (sig = ECDSA_SIG_new()))                                    return p_free_verify_variables(key, pub_x, pub_y, sig, group, point);
    if (NULL == (sig_r = BN_new()))                                         return p_free_verify_variables(key, pub_x, pub_y, sig, group, point);
    if (NULL == (sig_s = BN_new()))                                         return p_free_verify_variables(key, pub_x, pub_y, sig, group, point);
    if (0 != p_create_sha256(message, size, hash, true))                          return p_free_verify_variables(key, pub_x, pub_y, sig, group, point);

    // Big number conversion
    BN_bin2bn(signature,        32, sig_r);
    BN_bin2bn(signature + 32,   32, sig_s);
    ECDSA_SIG_set0(sig,sig_r, sig_s);

    verified    = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, sig, key);

    // Cleanup (sig_r and sig_s are freed by the ECDSA_SIG)
    p_free_verify_variables(key, pub_x, pub_y, sig, group, point);

    // Output
    return (verified == 1) ? 0 : 1;
}


// HMAC
uint32_t p_free_hmac_variables(HMAC_CTX *a) {
    HMAC_CTX_free(a);

    return 1;
}

uint32_t hm_crypto_openssl_hmac(uint8_t *message, uint16_t size, uint8_t *key, uint8_t *hmac) {
    HMAC_CTX *ctx = NULL;
	uint8_t output[32];
	uint16_t roundedSize = 0;
#ifdef DYNAMIC_MEM_DATA
	uint8_t *data = (uint8_t *)malloc(MAX_COMMAND_SIZE);
#else
	uint8_t data[MAX_COMMAND_SIZE];
#endif

	get_roundoff_64(size, &roundedSize);

    // Initial
    ctx = HMAC_CTX_new();
    HMAC_CTX_reset(ctx);

	p_fill_to_roundedSize(message, size, roundedSize, data);
    HMAC_Init_ex(ctx, key, 32, EVP_sha256(), NULL);

    // HMAC calculations
	if (1 != HMAC_Update(ctx, data, roundedSize))      return p_free_hmac_variables(ctx);
    if (1 != HMAC_Final(ctx, output, NULL))    return p_free_hmac_variables(ctx);

    // Output
    memcpy(hmac, output, 32);

    // Cleanup
    p_free_hmac_variables(ctx);

#ifdef DYNAMIC_MEM_DATA
	free(data);
#endif

    return 0;
}


// AES
uint32_t hm_crypto_openssl_aes_iv(uint8_t *key, uint8_t *iv, uint8_t *iv_out) {
    AES_KEY aes;
    uint8_t iv2[16];

    // Sets the key for AES
    if (0 != AES_set_encrypt_key(key, 128, &aes))    return 1;

    // Creates the Block Cipher (IV2)
    AES_ecb_encrypt(iv, iv2, &aes, AES_ENCRYPT);

    // Output
    memcpy(iv_out, iv2, 16);

    return 0;
}


// DH
uint32_t p_free_dh_variables(EC_KEY *a, BIGNUM *b, BIGNUM *c, BIGNUM *d, EC_POINT *e, BN_CTX *f) {
    EC_KEY_free(a);
    BN_clear_free(b);
    BN_clear_free(c);
    BN_clear_free(d);
    EC_POINT_clear_free(e);
    BN_CTX_free(f);

    return 1;
}

uint32_t hm_crypto_openssl_dh(uint8_t *private_key, uint8_t *public_key, uint8_t *shared_key) {
    EC_KEY *key = NULL;
    BIGNUM *pri_bn = NULL;
    BIGNUM *pub_x = NULL;
    BIGNUM *pub_y = NULL;
    EC_POINT *point = NULL;
    BN_CTX *context = NULL;
    uint8_t output[32];

    // Variable creation
    if (NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) return 1;
    if (NULL == (pri_bn = BN_new()))                            return p_free_dh_variables(key, pri_bn, pub_x, pub_y, point, context);

    // Crypto calculations
    if (NULL == BN_bin2bn(private_key, 32, pri_bn))             return p_free_dh_variables(key, pri_bn, pub_x, pub_y, point, context);
    if (1 != EC_KEY_set_private_key(key, pri_bn))               return p_free_dh_variables(key, pri_bn, pub_x, pub_y, point, context);

    // Variable creation
    if (NULL == (pub_x = BN_new()))                             return p_free_dh_variables(key, pri_bn, pub_x, pub_y, point, context);
    if (NULL == (pub_y = BN_new()))                             return p_free_dh_variables(key, pri_bn, pub_x, pub_y, point, context);

    // Big number conversion
    BN_bin2bn(public_key,       32, pub_x);
    BN_bin2bn(public_key + 32,  32, pub_y);

    // Variable creation
    if (NULL == (point = EC_POINT_new(EC_KEY_get0_group(key)))) return p_free_dh_variables(key, pri_bn, pub_x, pub_y, point, context);
    if (NULL == (context = BN_CTX_new()))                       return p_free_dh_variables(key, pri_bn, pub_x, pub_y, point, context);

    // Crypto calculations
    if (1 != EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(key), point, pub_x, pub_y, context))
                                                                return p_free_dh_variables(key, pri_bn, pub_x, pub_y, point, context);
    if (-1 == ECDH_compute_key(&output, 32, point, key, 0))     return p_free_dh_variables(key, pri_bn, pub_x, pub_y, point, context);

    // Output
    memcpy(shared_key, output, 32);

    // Cleanup
    p_free_dh_variables(key, pri_bn, pub_x, pub_y, point, context);

    return 0;
}

uint32_t hm_crypto_openssl_random(uint16_t count, uint8_t *bytes)
{
    uint8_t *tempBytes = (uint8_t *)malloc(count);

    memset(tempBytes, 0x00, count);

    if (RAND_bytes(tempBytes, count) != 1) return -1;

    // Output
    memcpy(bytes, tempBytes, count);

    // Cleanup
    free(tempBytes);

    return 0;
}

// JSON Web Token

uint32_t hm_crypto_openssl_jwt_signature(uint8_t *message, uint8_t size, uint8_t *private_key, uint8_t *signature) {
    return  p_create_signature(message, size, private_key, signature, false);
}

uint32_t hm_crypto_openssl_jwt_sha(uint8_t *nonce, uint8_t size, uint8_t *hash) {
    return p_create_sha256(nonce, size, hash, false);
}
