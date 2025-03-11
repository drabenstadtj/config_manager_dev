#ifndef KEY_GENERATION_H
#define KEY_GENERATION_H

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <stdint.h>

// Functions for key generation
EVP_PKEY *generate_rsa_key(int bits);
void free_rsa_key(EVP_PKEY *pkey);
char *get_public_key(EVP_PKEY *pkey);
char *get_encrypted_private_key(EVP_PKEY *pkey, const char *passphrase);

// Functions for generating specific keys
char *generate_spines_internal_public_key();
char *generate_spines_external_public_key();
char *generate_spines_internal_private_key();
char *generate_spines_external_private_key();
char *generate_tpm_public_key();
char *generate_instance_public_key();
char *generate_instance_private_key();
char *generate_prime_threshold_key_share();
char *generate_sm_threshold_key_share();

#endif /* KEY_GENERATION_H */