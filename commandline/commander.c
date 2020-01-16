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

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../Crypto.h"
#include "printer.h"


typedef struct flags_struct {
    bool raw;
    bool dev;
    bool pad;
} flags_struct;


bool hasFlag(char *arg, char *shortFlag, char *longFlag) {
    bool hasShortFlag = strcmp(arg, shortFlag) == 0;
    bool hasLongFlag = strcmp(arg, longFlag) == 0;

    return hasShortFlag || hasLongFlag;
}

void hexstr_to_char(const char* hexstr, char *output) {
    size_t len = strlen(hexstr);
    size_t final_len = len / 2;
    unsigned char* chrs = (unsigned char*)malloc((final_len) * sizeof(*chrs));

    for (size_t i = 0, j = 0; j < final_len; i += 2, j++) {
        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
    }

    memcpy(output, chrs, final_len);
}

int handle_keys(char *input[], int count, flags_struct flags) {
    uint8_t private_key[32];
    uint8_t public_key[64];
    uint32_t result = -1;
    bool is_special_pub = (count >= 4) && (strcmp(input[2], "pub") == 0) && (strcmp(&input[3][0], "-") != 0);
    bool is_only_pub = (count >= 3) && (strcmp(input[2], "pub") == 0);
    bool is_only_pri = (count >= 3) && (strcmp(input[2], "pri") == 0);

    // Make a public key from the private OR both
    if (is_special_pub) {
        hexstr_to_char(input[3], (char *)private_key);

        result = hm_crypto_openssl_create_keys(private_key, public_key, false);
    }
    else {
        result = hm_crypto_openssl_create_keys(private_key, public_key, true);
    }

    // If generation successful, print the results
    if (result == 0) {
        if (flags.pad) printf("\n");

        // Print the PRIVATE key
        if (!is_special_pub && !is_only_pub) {
            if (!flags.raw) printf("PRIVATE: ");

            print_hex(private_key, 32, flags.dev);
            printf("\n");
        }

        // Print the PUBLIC key
        if (!is_only_pri) {
            if (!flags.raw) printf("PUBLIC:  ");

            print_hex(public_key, 64, flags.dev);
            printf("\n");
        }

        if (flags.pad) printf("\n");
    }
    else {
        return -1;
    }

    return 0;
}

int handle_sign(char *input[], int count, flags_struct flags) {
    if (count >= 4) {
        if (strlen(input[3]) != 64) return -1;

        size_t msg_len = strlen(input[2]) / 2;
        uint8_t message[msg_len];
        uint8_t private_key[32];
        uint8_t signature[64];

        memset(signature, 0x00, 64);

        hexstr_to_char(input[2], (char *)message);
        hexstr_to_char(input[3], (char *)private_key);

        uint32_t result = hm_crypto_openssl_signature(message, msg_len, private_key, signature);

        if (result == 0) {
            if (flags.pad) printf("\n");

            if (!flags.raw) printf("SIGNATURE: ");

            print_hex(signature, 64, flags.dev);
            printf("\n");

            if (flags.pad) printf("\n");
        }
        else {
            return -1;
        }
    }
    else {
        return -1;
    }

    return 0;
}

int handle_verify(char *input[], int count, flags_struct flags) {
    if (count < 5) return -1;
    if (strlen(input[3]) != 128) return -1;
    if (strlen(input[4]) != 128) return -1;

    size_t msg_len = strlen(input[2]) / 2;

    uint8_t message[msg_len];
    uint8_t signature[64];
    uint8_t public_key[64];

    hexstr_to_char(input[2], (char *)message);
    hexstr_to_char(input[3], (char *)signature);
    hexstr_to_char(input[4], (char *)public_key);

    uint32_t result = hm_crypto_openssl_verify(message, msg_len, public_key, signature);

    // Print out the result
    if (flags.pad) printf("\n");

    if (flags.raw) {
        if (result == 0) {
            printf("1\n");
        }
        else {
            printf("0\n");
        }
    }
    else {
        printf("VERIFY: ");

        if (result == 0) {
            printf("CORRECT\n");
        }
        else {
            printf("FALSE\n");
        }
    }

    if (flags.pad) printf("\n");


    return 0;
}

int handle_hmac(char *input[], int count, flags_struct flags) {
    if (count < 4) return -1;
    if (strlen(input[3]) != 64) return -1;

    size_t msg_len = strlen(input[2]) / 2;

    uint8_t message[msg_len];
    uint8_t key[32];
    uint8_t hmac[32];

    hexstr_to_char(input[2], (char *)message);
    hexstr_to_char(input[3], (char *)key);

    if (hm_crypto_openssl_hmac(message, msg_len, key, hmac) != 0) return -1;

    // Print out the result
    if (flags.pad) printf("\n");

    if (!flags.raw) printf("HMAC: ");

    print_hex(hmac, 32, flags.dev);
    printf("\n");

    if (flags.pad) printf("\n");


    return 0;
}

int handle_hmac_verify(char *input[], int count, flags_struct flags) {
    if (count < 5) return -1;
    if (strlen(input[3]) != 64) return -1;
    if (strlen(input[4]) != 64) return -1;

    size_t msg_len = strlen(input[2]) / 2;

    uint8_t message[msg_len];
    uint8_t key[32];
    uint8_t hmac_incoming[32];
    uint8_t hmac[32];

    hexstr_to_char(input[2], (char *)message);
    hexstr_to_char(input[3], (char *)key);
    hexstr_to_char(input[4], (char *)hmac_incoming);

    if (hm_crypto_openssl_hmac(message, msg_len, key, hmac) != 0) return -1;

    int result = memcmp(hmac, hmac_incoming, 32);

    // Print out the result
    if (flags.pad) printf("\n");

    if (flags.raw) {
        if (result == 0) {
            printf("1\n");
        }
        else {
            printf("0\n");
        }
    }
    else {
        printf("HMAC VERIFY: ");

        if (result == 0) {
            printf("CORRECT\n");
        }
        else {
            printf("FALSE\n");
        }
    }

    if (flags.pad) printf("\n");


    return 0;
}

int handle_access_cert(char *input[], int count, flags_struct flags) {
    // Version defaults to 1
    uint8_t version = 1;

    // Extract the version
    for (int i = 1; i < count; i++) {
        char *argument = input[i];

        if (hasFlag(argument, "-ac0", "-ac0")) {
            version = 0;
        }
        else if (hasFlag(argument, "-ac1", "-ac1")) {   // A bit redunant currently, but for the future...
            version = 1;
        }
    }


    size_t cert_len;
    uint8_t cert[256];


    // Handle different versions
    if (version == 0) {
        if (count < 8) return -1;
        if (strlen(input[2]) != 18) return -1;
        if (strlen(input[3]) != 18) return -1;
        if (strlen(input[4]) != 128) return -1;
        if (strlen(input[5]) != 10) return -1;
        if (strlen(input[6]) != 10) return -1;

        uint8_t g_serial[9];
        uint8_t g_public_key[64];
        uint8_t p_serial[9];
        uint8_t s_date[5];
        uint8_t e_date[5];

        hexstr_to_char(input[2], (char *)p_serial);
        hexstr_to_char(input[3], (char *)g_serial);
        hexstr_to_char(input[4], (char *)g_public_key);
        hexstr_to_char(input[5], (char *)s_date);
        hexstr_to_char(input[6], (char *)e_date);

        // Handle permissions
        size_t perm_len = 0;
        uint8_t permissions[16];

        if ((count >= 9) && (input[7][0] != '-')) {
            perm_len = strlen(input[7]) / 2;

            if (perm_len > 16) return -1;

            hexstr_to_char(input[7], (char *)permissions);
        }

        // Combine the certificate
        cert_len = 9 + 64 + 9 + 5 + 5 + 1 + perm_len;

        memcpy(cert, g_serial, 9);
        memcpy((cert + 9), g_public_key, 64);
        memcpy((cert + 9 + 64), p_serial, 9);
        memcpy((cert + 9 + 64 + 9), s_date, 5);
        memcpy((cert + 9 + 64 + 9 + 5), e_date, 5);

        cert[9 + 64 + 9 + 5 + 5] = perm_len;

        if (perm_len > 0) memcpy((cert + cert_len - perm_len), permissions, perm_len);
    }
    else if (version == 1) {
        if (count < 8) return -1;
        if (strlen(input[2]) != 8) return -1;
        if (strlen(input[3]) != 18) return -1;
        if (strlen(input[4]) != 18) return -1;
        if (strlen(input[5]) != 128) return -1;
        if (strlen(input[6]) != 10) return -1;
        if (strlen(input[7]) != 10) return -1;

        uint8_t issuer[4];
        uint8_t p_serial[9];
        uint8_t g_serial[9];
        uint8_t g_public_key[64];
        uint8_t s_date[5];
        uint8_t e_date[5];

        hexstr_to_char(input[2], (char *)issuer);
        hexstr_to_char(input[3], (char *)p_serial);
        hexstr_to_char(input[4], (char *)g_serial);
        hexstr_to_char(input[5], (char *)g_public_key);
        hexstr_to_char(input[6], (char *)s_date);
        hexstr_to_char(input[7], (char *)e_date);

        // Handle permissions
        size_t perm_len = 0;
        uint8_t permissions[16];

        if ((count >= 9) && (input[8][0] != '-')) {
            perm_len = strlen(input[8]) / 2;

            if (perm_len > 16) return -1;

            hexstr_to_char(input[8], (char *)permissions);
        }

        // Combine the certificate
        cert_len = 1 + 4 + 9 + 9 + 64 + 5 + 5 + 1 + perm_len;

        cert[0] = version; // The version byte

        memcpy((cert + 1), issuer, 4);
        memcpy((cert + 1 + 4), p_serial, 9);
        memcpy((cert + 1 + 4 + 9), g_serial, 9);
        memcpy((cert + 1 + 4 + 9 + 9), g_public_key, 64);
        memcpy((cert + 1 + 4 + 9 + 9 + 64), s_date, 5);
        memcpy((cert + 1 + 4 + 9 + 9 + 64 + 5), e_date, 5);

        cert[1 + 4 + 9 + 9 + 64 + 5 + 5] = perm_len;

        if (perm_len > 0) memcpy((cert + cert_len - perm_len), permissions, perm_len);
    }
    else {
        return -1;
    }


    // Print out the result
    if (flags.pad) printf("\n");

    if (!flags.raw) printf("ACCESS CERT: ");

    print_hex(cert, cert_len, flags.dev);
    printf("\n");

    if (flags.pad) printf("\n");


    return 0;
}

int handle_device_cert(char *input[], int count, flags_struct flags) {
    if (count < 6) return -1;
    if (strlen(input[2]) != 8) return -1;
    if (strlen(input[3]) != 24) return -1;
    if (strlen(input[4]) != 18) return -1;
    if (strlen(input[5]) != 128) return -1;

    // Print out the result
    if (flags.pad) printf("\n");

    if (!flags.raw) printf("DEVICE CERT: ");

    printf("%s", input[2]); // Issuer
    printf("%s", input[3]); // App ID
    printf("%s", input[4]); // Serial
    printf("%s", input[5]); // Public key
    printf("\n");

    if (flags.pad) printf("\n");

    
    return 0;
}

int handle_aes(char *input[], int count, flags_struct flags) {
    if (count < 4) return -1;
    if (strlen(input[2]) != 32) return -1;
    if (strlen(input[3]) != 32) return -1;

    uint8_t plain_text[16];
    uint8_t key[16];
    uint8_t cipher_text[16];

    hexstr_to_char(input[2], (char *)plain_text);
    hexstr_to_char(input[3], (char *)key);

    if (hm_crypto_openssl_aes_iv(key, plain_text, cipher_text) != 0) return -1;

    // Print out the result
    if (flags.pad) printf("\n");

    if (!flags.raw) printf("AES: ");

    print_hex(cipher_text, 16, flags.dev);
    printf("\n");

    if (flags.pad) printf("\n");


    return 0;
}

int handle_dh(char *input[], int count, flags_struct flags) {
    if (count < 4) return -1;
    if (strlen(input[2]) != 64) return -1;
    if (strlen(input[3]) != 128) return -1;

    uint8_t private_key[32];
    uint8_t public_key[64];
    uint8_t shared_key[32];

    hexstr_to_char(input[2], (char *)private_key);
    hexstr_to_char(input[3], (char *)public_key);

    if (hm_crypto_openssl_dh(private_key, public_key, shared_key) != 0) return -1;

    // Print out the result
    if (flags.pad) printf("\n");

    if (!flags.raw) printf("DH: ");

    print_hex(shared_key, 32, flags.dev);
    printf("\n");

    if (flags.pad) printf("\n");


    return 0;
}

int handle_random(char *input[], int count, flags_struct flags) {
    if (count < 3) return -1;

    uint16_t bytes_count = atoi(input[2]);
    uint8_t bytes[bytes_count];

    if (hm_crypto_openssl_random(bytes_count, bytes) != 0) return -1;

    // Print out the result
    if (flags.pad) printf("\n");

    if (!flags.raw) printf("RANDOM: ");

    print_hex(bytes, bytes_count, flags.dev);
    printf("\n");

    if (flags.pad) printf("\n");

    
    return 0;
}

int handle_compress(char *input[], int count, flags_struct flags) {
    // TODO: Compress isn't implemented currently
    // On the count of how hard it sucks to do string-stuff in C

    return 0;
}


int parse_command(int count, char *input[]) {
    char *command_name = input[1];
    int result = 0;


    // Get the flags
    flags_struct flags;

    flags.raw = false;
    flags.dev = false;
    flags.pad = false;

    for (int i = 1; i < count; i++) {
        char *argument = input[i];

        if (hasFlag(argument, "-r", "--raw")) {
            flags.raw = true;
        }
        else if (hasFlag(argument, "-d", "--dev")) {
            flags.dev = true;
        }
        else if (hasFlag(argument, "-p", "--pad")) {
            flags.pad = true;
        }
    }


    // Find the command
    if (strcmp(command_name, "keys") == 0) {
        result = handle_keys(input, count, flags);
    }
    else if (strcmp(command_name, "sign") == 0) {
        result = handle_sign(input, count, flags);
    }
    else if (strcmp(command_name, "verify") == 0) {
        result = handle_verify(input, count, flags);
    }
    else if (strcmp(command_name, "hmac") == 0) {
        result = handle_hmac(input, count, flags);
    }
    else if (strcmp(command_name, "hmacver") == 0) {
        result = handle_hmac_verify(input, count, flags);
    }
    else if (strcmp(command_name, "access") == 0) {
        result = handle_access_cert(input, count, flags);
    }
    else if (strcmp(command_name, "device") == 0) {
        result = handle_device_cert(input, count, flags);
    }
    else if (strcmp(command_name, "aes") == 0) {
        result = handle_aes(input, count, flags);
    }
    else if (strcmp(command_name, "dh") == 0) {
        result = handle_dh(input, count, flags);
    }
    else if (strcmp(command_name, "rndm") == 0) {
        result = handle_random(input, count, flags);
    }
//    else if (strcmp(command_name, "compress") == 0) {
//        result = handle_compress(input, count, flags);
//    }
    else {
        result = -1;
    }

    return result;
}
