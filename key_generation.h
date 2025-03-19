#ifndef KEY_GENERATION_H
#define KEY_GENERATION_H

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <stdint.h>

// Struct to hold the signature and its length
typedef struct
{
    unsigned char *signature;
    size_t length;
} Signature;

// Key generation functions
EVP_PKEY *generate_rsa_key(int bits);
void free_rsa_key(EVP_PKEY *pkey);

// Key extraction functions
char *get_public_key(EVP_PKEY *pkey);
char *get_private_key(EVP_PKEY *pkey);
char *get_encrypted_private_key(EVP_PKEY *pkey, const char *passphrase);

// File I/O functions
int write_key_to_file(const char *filename, const char *key);
unsigned char *read_file(const char *filename, size_t *length);

// Signing and verification functions
Signature sign_file(const char *file_path, const char *priv_key_path);
int verify_signature(const char *file_path, const char *pub_key_path, const unsigned char *signature, size_t sig_len);

// Utility function to free signature memory
void free_signature(Signature *sig);

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

#define TMP_KEY_DIR "tpm_keys/"

#endif /* KEY_GENERATION_H */