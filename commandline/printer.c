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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>


void p_print_keys_help() {
    printf("  keys: optional \"pri\" | \"pub\" <private key>\n");
    printf("\tGenerate private and public keys - defaults to both.\n");
    printf("\n");
    printf("\t<private key>\t32 bytes\n");
    printf("\n");
}

void p_print_sign_help() {
    printf("  sign: <message> <private key>\n");
    printf("\tGenerate a Signature for a Message.\n");
    printf("\n");
    printf("\t<message>\tn bytes (up to 256)\n");
    printf("\t<private key>\t32 bytes\n");
    printf("\n");
}

void p_print_verify_help() {
    printf("  verify: <message> <signature> <public key>\n");
    printf("\tVerify a Message with a Signature.\n");
    printf("\n");
    printf("\t<message>\tn bytes (up to 256)\n");
    printf("\t<signature>\t64 bytes\n");
    printf("\t<public key>\t64 bytes\n");
    printf("\n");
}

void p_print_hmac_help() {
    printf("  hmac: <message> <key>\n");
    printf("\tGenerate an HMAC for a Message.\n");
    printf("\n");
    printf("\t<message>\tn bytes\n");
    printf("\t<key>\t\t32 bytes\n");
    printf("\n");
}

void p_print_hmac_ver_help() {
    printf("  hmacver: <message> <key> <hmac>\n");
    printf("\tVerify an HMAC for a message.\n");
    printf("\n");
    printf("\t<message>\tn bytes\n");
    printf("\t<key>\t\t32 bytes\n");
    printf("\t<hmac>\t\t32 bytes\n");
    printf("\n");
}

void p_print_access_cert_help() {
    printf("  access: <issuer> <providing serial> <gaining serial> <gaining public key> <start date> <end date> <permissions [optional]>\n");
    printf("\tCombine an Access Certificate.\n");
    printf("\n");
    printf("\t<issuer>\t\t4 bytes\n");
    printf("\t<serials>\t\t9 bytes\n");
    printf("\t<public key>\t\t64 bytes\n");
    printf("\t<dates>\t\t\t5 bytes, format: YYMMDDHHmm\n");
    printf("\t<permissions>\t\t0 - 16 bytes [optional]\n");
    printf("\n");
    printf("\tAdditional flags:\n");
    printf("\n");
    printf("\t -ac0\tVersion 0 - <issuer> field must be ommited.\n");
    printf("\t -ac1\tVersion 1 - default version (no need to use this flag).\n");
    printf("\n");
}

void p_print_device_cert_help() {
    printf("  device: <issuer> <appID> <serial> <public key>\n");
    printf("\tCombine a Device Certificate.\n");
    printf("\n");
    printf("\t<issuer>\t4 bytes\n");
    printf("\t<appID>\t\t12 bytes\n");
    printf("\t<serial>\t9 bytes\n");
    printf("\t<public key>\t64 bytes\n");
    printf("\n");
}

void p_print_aes_help() {
    printf("  aes: <plain text> <key>\n");
    printf("\tEncrypt (or decrypt) the Plain text using AES.\n");
    printf("\n");
    printf("\t<plain text>\t16 bytes\n");
    printf("\t<key>\t\t16 bytes\n");
    printf("\n");
}

void p_print_dh_help() {
    printf("  dh: <private key> <public key>\n");
    printf("\tCreatea shared key with Diffie-Hellman.\n");
    printf("\n");
    printf("\t<private key>\t32 bytes\n");
    printf("\t<public key>\t64 bytes\n");
    printf("\n");
}

void p_print_random_help() {
    printf("  rndm: <count>\n");
    printf("\tGenerate cryptographically secure Random bytes (.i.e. for a nonce).\n");
    printf("\n");
    printf("\t<count>\t\tinteger [1, 256]\n");
    printf("\n");
}

void p_print_compress_help() {
    printf("  compress: [<byte>] where every byte is prefixed with \"0x\"\n");
    printf("\tCompress an Hexadecimal array into a compact one - can be reversed with the flag -d\n");
    printf("\n");
    printf("\tExample input \"0xAA, 0xBB, 0xCC\", output \"AABBCC\"\n");
    printf("\n");
}

void p_print_commands(char *name) {
    printf("Usage: %s <command> [<args>] [<flags>]\n", name);
    printf("\n");
    printf("  -COMMANDS-\n");

    p_print_keys_help();
    p_print_sign_help();
    p_print_verify_help();
    p_print_hmac_help();
    p_print_hmac_ver_help();
    p_print_access_cert_help();
    p_print_device_cert_help();
    p_print_aes_help();
    p_print_dh_help();
    p_print_random_help();

    // TODO: Compress isn't implemented currently
    // On the count of how hard it sucks to do string-stuff in C
//    p_print_compress_help();

    printf("\n");
}

void p_print_flags() {
    printf("  -FLAGS-\n");
    printf("  -h, --help:\tPrint the info for a command.\n");
    printf("  -r, --raw:\tOutput only raw / hex data like \"AABBCC\"\n");
    printf("  -d, --dev:\tOutput hexadecimal array like \"0xAA, 0xBB, 0xCC\"\n");
    printf("  -p, --pad:\tAdds extra lines above and below the output for easier reading.\n");
    printf("  -v, --ver:\tCryptotool's version\n");
    printf("\n");
}


void print_help(char *name, bool fullHelp, char *specificCmd) {
    printf("\n");

    if (fullHelp) {
        printf("\n");

        p_print_commands(name);
        p_print_flags();

        printf("All data entered must be in hexadecimal (1 byte == 2 characters)\n");
        printf("\n");
    }
    else {
        if (strcmp(specificCmd, "keys") == 0) {
            p_print_keys_help();
        }
        else if (strcmp(specificCmd, "sign") == 0) {
            p_print_sign_help();
        }
        else if (strcmp(specificCmd, "verify") == 0) {
            p_print_verify_help();
        }
        else if (strcmp(specificCmd, "hmac") == 0) {
            p_print_hmac_help();
        }
        else if (strcmp(specificCmd, "hmacver") == 0) {
            p_print_hmac_ver_help();
        }
        else if (strcmp(specificCmd, "access") == 0) {
            p_print_access_cert_help();
        }
        else if (strcmp(specificCmd, "device") == 0) {
            p_print_device_cert_help();
        }
        else if (strcmp(specificCmd, "aes") == 0) {
            p_print_aes_help();
        }
        else if (strcmp(specificCmd, "dh") == 0) {
            p_print_dh_help();
        }
        else if (strcmp(specificCmd, "rndm") == 0) {
            p_print_random_help();
        }
//        else if (strcmp(specificCmd, "compress") == 0) {
//            p_print_compress_help();
//        }
        else {
            print_help(name, true, NULL);
        }
    }
}

void print_hex(uint8_t *input, uint16_t count, bool as_dev) {
    for (int i = 0; i < count; i++) {
        if (as_dev) {
            printf("0x%02X", input[i]);

            if (i != (count - 1)) {
                printf(", ");
            }
        }
        else {
            printf("%02X", input[i]);
        }
    }
}
