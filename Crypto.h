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

#ifndef Crypto_h
#define Crypto_h

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif

// CRUNUSED macro
#define CRUNUSED(x) (void)(sizeof(x))

// TODO: Add the inputs/outputs bytes sizes

/** @brief Creates cryptographical keys for the p256 elliptic curve.
 *
 *  Can also be used to generate the public key from the private, if the supplied private_key is filled.
 *
 *  @param private_key      The output or input for the private key.
 *  @param public_key       The output for the public key.
 *  @param create_both      If this is 'true', both keys are created. Otherwise the public key is created from the private.
 *
 *  @return                 0 for success
 */
uint32_t hm_crypto_openssl_create_keys(uint8_t *private_key, uint8_t *public_key, bool create_both);

/** @brief Creates a cryptographical signature for a message.
 *
 *  @param message          The message that's going to be signed.
 *  @param size             The size of the message.
 *  @param private_key      The private key to be used for signing.
 *  @param signature        The generated signature for the message.
 *
 *  @return                 0 for success
 */
uint32_t hm_crypto_openssl_signature(uint8_t *message, uint8_t size, uint8_t *private_key, uint8_t *signature);

/** @brief Verifies a cryptographical signature of a message.
 *
 *  @param message          The message that's signature is verified.
 *  @param size             The size of the message.
 *  @param public_key       The public key of the signature.
 *  @param signature        The signature of the message.
 *
 *  @return                 0 for success
 */
uint32_t hm_crypto_openssl_verify(uint8_t *message, uint8_t size, uint8_t *public_key, uint8_t *signature);

/** @brief Creates an HMAC for a message.
 *
 *  @param message          The message that's used for the HMAC.
 *  @param size             The size of the message.
 *  @param key              The key to be used for HMAC.
 *  @param hmac             The HMAC for the message.
 *
 *  @return                 0 for success
 */
uint32_t hm_crypto_openssl_hmac(uint8_t *message, uint16_t size, uint8_t *key, uint8_t *hmac);

/** @brief Encrypt the injection vector for use in block cipher.
 *
 *  @param key              The key for the BCE.
 *  @param iv               The inital IV.
 *  @param iv_out           The encrypted IV.
 *
 *  @return                 0 for success
 */
uint32_t hm_crypto_openssl_aes_iv(uint8_t *key, uint8_t *iv, uint8_t *iv_out);

/** @brief Creates cryptographical shared key with Diffie-Hellman
 *
 *  @param private_key      The private key for process.
 *  @param public_key       The public key for the process.
 *  @param shared_key       The output of DH.
 *
 *  @return                 0 for success
 */
uint32_t hm_crypto_openssl_dh(uint8_t *private_key, uint8_t *public_key, uint8_t *shared_key);

/** @brief Creates cryptographically secure random bytes.
 *
 *  @param count            The number of bytes to generate.
 *  @param bytes            The output of the bytes.
 *
 *  @return                 0 for success
 */
uint32_t hm_crypto_openssl_random(uint16_t count, uint8_t *bytes);

/** @brief Creates a cryptographical signature for a JWT message.
 *
 *  @param message          The message that's going to be signed.
 *  @param size             The size of the message.
 *  @param private_key      The private key to be used for signing.
 *  @param signature        The generated signature for the message.
 *
 *  @return                 0 for success
 */
uint32_t hm_crypto_openssl_jwt_signature(uint8_t *message, uint8_t size, uint8_t *private_key, uint8_t *signature);

/** @brief Creates a cryptographical hash of the JWT nonce.
 *
 *  @param nonce            The nonce that's used to generate the hash.
 *  @param size             The size of the nonce.
 *  @param hash             The generated hash.
 *
 *  @return                 0 for success
 */
uint32_t hm_crypto_openssl_jwt_sha(uint8_t *nonce, uint8_t size, uint8_t *hash);

#ifdef __cplusplus
}
#endif

#endif /* Crypto_h */
