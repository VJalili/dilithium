#include <stdio.h>
#include <stdint.h>
#include "sign.h"
#include "params.h"

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];   // Public key
    uint8_t sk[CRYPTO_SECRETKEYBYTES];   // Secret (private) key
    uint8_t sig[CRYPTO_BYTES];           // Signature
    size_t siglen;                       // Signature length

    // Your custom data
    uint8_t message[] = "Your custom byte array data here";
    size_t message_len = sizeof(message);

    // Generate a key pair
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "Failed to generate key pair\n");
        return 1;
    }

    // Sign the message
    if (crypto_sign_signature(sig, &siglen, message, message_len, sk) != 0) {
        fprintf(stderr, "Failed to sign message\n");
        return 1;
    }

    // Verify the signature
    if (crypto_sign_verify(sig, siglen, message, message_len, pk) != 0) {
        fprintf(stderr, "Failed to verify signature\n");
        return 1;
    } else {
        printf("Signature verified successfully!\n");
    }

    return 0;
}
