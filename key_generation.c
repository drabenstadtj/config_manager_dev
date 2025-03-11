
#include "key_generation.h"
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Generate an RSA key using EVP API
EVP_PKEY* generate_rsa_key(int bits) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create EVP_PKEY_CTX\n");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        fprintf(stderr, "Error: RSA key generation initialization failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Error: RSA key generation failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Convert EVP_PKEY to a PEM formatted string (Public Key)
char* get_public_key(EVP_PKEY *pkey) {
    if (!pkey) {
        fprintf(stderr, "Error: Invalid key\n");
        return NULL;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "Error: Failed to create BIO\n");
        return NULL;
    }

    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        fprintf(stderr, "Error: Failed to write public key to BIO\n");
        BIO_free(bio);
        return NULL;
    }

    size_t len = BIO_pending(bio);
    char *pem_key = malloc(len + 1);
    if (!pem_key) {
        fprintf(stderr, "Error: Memory allocation failed for public key\n");
        BIO_free(bio);
        return NULL;
    }

    BIO_read(bio, pem_key, len);
    pem_key[len] = '\0';

    BIO_free(bio);
    return pem_key;
}

// Convert EVP_PKEY to an encrypted PEM formatted string (Private Key)
char* get_encrypted_private_key(EVP_PKEY *pkey, const char *passphrase) {
    if (!pkey || !passphrase) {
        fprintf(stderr, "Error: Invalid parameters for private key encryption\n");
        return NULL;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "Error: Failed to create BIO\n");
        return NULL;
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, EVP_aes_256_cbc(), 
                                  (unsigned char*)passphrase, strlen(passphrase), NULL, NULL)) {
        fprintf(stderr, "Error: Failed to write encrypted private key to BIO\n");
        BIO_free(bio);
        return NULL;
    }

    size_t len = BIO_pending(bio);
    char *pem_key = malloc(len + 1);
    if (!pem_key) {
        fprintf(stderr, "Error: Memory allocation failed for private key\n");
        BIO_free(bio);
        return NULL;
    }

    BIO_read(bio, pem_key, len);
    pem_key[len] = '\0';

    BIO_free(bio);
    return pem_key;
}

// Free EVP_PKEY structure
void free_rsa_key(EVP_PKEY *pkey) {
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
}

// Generate Spines Internal Public Key (RSA-2048)
char* generate_spines_internal_public_key() {
    EVP_PKEY *key = generate_rsa_key(2048);
    if (!key) return NULL;

    char* pub_key = get_public_key(key);
    free_rsa_key(key);
    return pub_key;
}

// Generate Spines Internal Private Key (Encrypted RSA-2048)
char* generate_spines_internal_private_key() {
    EVP_PKEY *key = generate_rsa_key(2048);
    if (!key) return NULL;

    // assuming using a passphrase, NEED TO ASK
    char *passphrase = "default_passphrase"; 
    char* enc_priv_key = get_encrypted_private_key(key, passphrase);
    free_rsa_key(key);
    return enc_priv_key;
}

// Generate Spines External Public Key (Same as Internal)
char* generate_spines_external_public_key() {
    return generate_spines_internal_public_key();
}

// Generate Spines External Private Key (Same as Internal)
char* generate_spines_external_private_key() {
    return generate_spines_internal_private_key();
}

// Generate TPM Public Key (RSA-3072)
char* generate_tpm_public_key() {
    EVP_PKEY *key = generate_rsa_key(3072);
    if (!key) return NULL;

    char* pub_key = get_public_key(key);
    free_rsa_key(key);
    return pub_key;
}

// Generate Instance Public Key (RSA-2048)
char* generate_instance_public_key() {
    EVP_PKEY *key = generate_rsa_key(2048);
    if (!key) return NULL;

    char* pub_key = get_public_key(key);
    free_rsa_key(key);
    return pub_key;
}

// Generate Instance Private Key (RSA-2048, Encrypted)
char* generate_instance_private_key() {
    EVP_PKEY *key = generate_rsa_key(2048);
    if (!key) return NULL;

    char *passphrase = "instance_passphrase"; 
    char* enc_priv_key = get_encrypted_private_key(key, passphrase);
    free_rsa_key(key);
    return enc_priv_key;
}

// Generate Prime Threshold Key Share (RSA-2048, Encrypted)
char* generate_prime_threshold_key_share() {
    return generate_instance_private_key();
}

// Generate SM Threshold Key Share (Same as Prime Threshold)
char* generate_sm_threshold_key_share() {
    return generate_instance_private_key();
}