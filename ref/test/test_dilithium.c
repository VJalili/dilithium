#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../randombytes.h"
#include "../sign.h"

#define MLEN 59
#define NTESTS 10000

void print_hex(const char *label, const uint8_t *data, size_t data_len) {
    printf("%s: ", label);
    for (size_t i = 0; i < data_len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main(void)
{
  size_t i, j;
  int ret;
  size_t mlen, smlen;
  uint8_t b;
  uint8_t m[MLEN + CRYPTO_BYTES];
  uint8_t m2[MLEN + CRYPTO_BYTES];
  uint8_t sm[MLEN + CRYPTO_BYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  for(i = 0; i < NTESTS; ++i) {
    randombytes(m, MLEN);

    crypto_sign_keypair(pk, sk);
    crypto_sign(sm, &smlen, m, MLEN, sk);
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);

    if(ret) {
      fprintf(stderr, "Verification failed\n");
      return -1;
    }
    if(smlen != MLEN + CRYPTO_BYTES) {
      fprintf(stderr, "Signed message lengths wrong\n");
      return -1;
    }
    if(mlen != MLEN) {
      fprintf(stderr, "Message lengths wrong\n");
      return -1;
    }
    for(j = 0; j < MLEN; ++j) {
      if(m2[j] != m[j]) {
        fprintf(stderr, "Messages don't match\n");
        return -1;
      }
    }

    randombytes((uint8_t *)&j, sizeof(j));
    do {
      randombytes(&b, 1);
    } while(!b);
    sm[j % (MLEN + CRYPTO_BYTES)] += b;
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);
    if(!ret) {
      fprintf(stderr, "Trivial forgeries possible\n");
      return -1;
    }
  }

  printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_BYTES = %d\n", CRYPTO_BYTES);

  printf("\n-------------------- my own test begin---------------------\n");

  //uint8_t pk[CRYPTO_PUBLICKEYBYTES];   // Public key
  //uint8_t sk[CRYPTO_SECRETKEYBYTES];   // Secret (private) key
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

  // Print the public and private keys
  print_hex("Public Key", pk, CRYPTO_PUBLICKEYBYTES);
  print_hex("Private Key", sk, CRYPTO_SECRETKEYBYTES);

  // Sign the message
  if (crypto_sign_signature(sig, &siglen, message, message_len, sk) != 0) {
      fprintf(stderr, "Failed to sign message\n");
      return 1;
  }

  // Print the signature
  print_hex("Signature", sig, siglen);

  // Verify the signature
  if (crypto_sign_verify(sig, siglen, message, message_len, pk) != 0) {
      fprintf(stderr, "Failed to verify signature\n");
      return 1;
  } else {
      printf("Signature verified successfully!\n");
  }

  printf("\n-------------------- my own test end---------------------\n");

  return 0;
}














/*/

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
}*/






