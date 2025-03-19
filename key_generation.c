#include "key_generation.h"
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Generate an RSA key using EVP API
EVP_PKEY *generate_rsa_key(int bits)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Creates a context for rsa keygen

    if (!ctx)
    {
        fprintf(stderr, "Error: Failed to create EVP_PKEY_CTX\n");
        return NULL;
    }

    // Initialize the key generation context and set the key length
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
    {
        fprintf(stderr, "Error: RSA key generation initialization failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // Generate the RSA key pair
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        fprintf(stderr, "Error: RSA key generation failed\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx); // Free the context after key generation
    return pkey;            // Return the generated key
}

// Convert EVP_PKEY to a PEM formatted string (Public Key)
char *get_public_key(EVP_PKEY *pkey)
{
    if (!pkey)
    {
        fprintf(stderr, "Error: Invalid key\n");
        return NULL;
    }

    BIO *bio = BIO_new(BIO_s_mem()); // Create a new in-memory BIO
    if (!bio)
    {
        fprintf(stderr, "Error: Failed to create BIO\n");
        return NULL;
    }

    // Write the public key to the BIO in PEM format
    if (!PEM_write_bio_PUBKEY(bio, pkey))
    {
        fprintf(stderr, "Error: Failed to write public key to BIO\n");
        BIO_free(bio);
        return NULL;
    }

    // Get the number of bytes stored in the BIO
    size_t len = BIO_pending(bio);
    char *pem_key = malloc(len + 1); // Allocate memory for the PEM string
    if (!pem_key)
    {
        fprintf(stderr, "Error: Memory allocation failed for public key\n");
        BIO_free(bio);
        return NULL;
    }

    BIO_read(bio, pem_key, len); // Read the PEM key from BIO into memory
    pem_key[len] = '\0';

    BIO_free(bio);
    return pem_key;
}

// Extracts an unencrypted private key as a PEM-formatted string
char *get_private_key(EVP_PKEY *pkey)
{
    if (!pkey)
    {
        fprintf(stderr, "Error: Invalid private key\n");
        return NULL;
    }

    BIO *bio = BIO_new(BIO_s_mem()); // Create an in-memory BIO
    if (!bio)
    {
        fprintf(stderr, "Error: Failed to create BIO\n");
        return NULL;
    }

    // Write the private key to the BIO in PEM format (unencrypted)
    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL))
    {
        fprintf(stderr, "Error: Failed to write private key to BIO\n");
        BIO_free(bio);
        return NULL;
    }

    // Get the length of the stored key
    size_t len = BIO_pending(bio);
    char *pem_key = malloc(len + 1);
    if (!pem_key)
    {
        fprintf(stderr, "Error: Memory allocation failed for private key\n");
        BIO_free(bio);
        return NULL;
    }

    // Read the private key from the BIO into memory
    BIO_read(bio, pem_key, len);
    pem_key[len] = '\0'; // Null-terminate the string

    BIO_free(bio);
    return pem_key; // Return the PEM-formatted private key
}

// Convert EVP_PKEY to an encrypted PEM formatted string (Private Key)
char *get_encrypted_private_key(EVP_PKEY *pkey, const char *passphrase)
{
    if (!pkey || !passphrase)
    {
        fprintf(stderr, "Error: Invalid parameters for private key encryption\n");
        return NULL;
    }

    BIO *bio = BIO_new(BIO_s_mem()); // Create a new in-memory BIO
    if (!bio)
    {
        fprintf(stderr, "Error: Failed to create BIO\n");
        return NULL;
    }

    // Write the private key to the BIO in encrypted PEM format using AES-256-CBC
    if (!PEM_write_bio_PrivateKey(bio, pkey, EVP_aes_256_cbc(),
                                  (unsigned char *)passphrase, strlen(passphrase), NULL, NULL))
    {
        fprintf(stderr, "Error: Failed to write encrypted private key to BIO\n");
        BIO_free(bio);
        return NULL;
    }

    // Get the number of bytes stored in the BIO
    size_t len = BIO_pending(bio);
    char *pem_key = malloc(len + 1); // Allocate memory for the PEM string
    if (!pem_key)
    {
        fprintf(stderr, "Error: Memory allocation failed for private key\n");
        BIO_free(bio);
        return NULL;
    }

    BIO_read(bio, pem_key, len); // Read the encrypted private key from BIO into memory
    pem_key[len] = '\0';

    BIO_free(bio);
    return pem_key;
}

// Free EVP_PKEY structure
void free_rsa_key(EVP_PKEY *pkey)
{
    if (pkey)
    {
        EVP_PKEY_free(pkey);
    }
}

// Write a key to a file
int write_key_to_file(const char *filename, const char *key)
{
    if (!filename || !key)
    {
        fprintf(stderr, "Error: Invalid filename or key\n");
        return -1;
    }

    FILE *file = fopen(filename, "w");
    if (!file)
    {
        perror("Error opening file for writing");
        return -1;
    }

    if (fprintf(file, "%s", key) < 0)
    {
        fprintf(stderr, "Error: Failed to write key to file\n");
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0; // Success
}

// Function to read a file into a buffer
unsigned char *read_file(const char *filename, size_t *length)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("Error opening file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    rewind(file);

    unsigned char *buffer = malloc(*length);
    if (!buffer)
    {
        perror("Memory allocation failed");
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, *length, file);
    fclose(file);
    return buffer;
}

// Function to sign a file and return a SignatureResult object
Signature sign_file(const char *file_path, const char *priv_key_path)
{
    Signature result = {NULL, 0}; // Initialize result

    // Read the file into memory
    size_t file_len;
    unsigned char *file_data = read_file(file_path, &file_len);
    if (!file_data)
    {
        return result;
    }

    // Load private key
    FILE *key_file = fopen(priv_key_path, "r");
    if (!key_file)
    {
        perror("Error opening private key file");
        free(file_data);
        return result;
    }

    EVP_PKEY *priv_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!priv_key)
    {
        ERR_print_errors_fp(stderr);
        free(file_data);
        return result;
    }

    // Create signing context
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        perror("EVP_MD_CTX_new failed");
        EVP_PKEY_free(priv_key);
        free(file_data);
        return result;
    }

    // Initialize signing with SHA-256
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, priv_key) != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(priv_key);
        free(file_data);
        return result;
    }

    // Update the digest with file data
    if (EVP_DigestSignUpdate(md_ctx, file_data, file_len) != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(priv_key);
        free(file_data);
        return result;
    }

    // Get the required size for the signature
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(priv_key);
        free(file_data);
        return result;
    }

    // Allocate memory for the signature
    unsigned char *signature = malloc(sig_len);
    if (!signature)
    {
        perror("Memory allocation failed");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(priv_key);
        free(file_data);
        return result;
    }

    // Generate the actual signature
    if (EVP_DigestSignFinal(md_ctx, signature, &sig_len) != 1)
    {
        ERR_print_errors_fp(stderr);
        free(signature);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(priv_key);
        free(file_data);
        return result;
    }

    // Cleanup and return result
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(priv_key);
    free(file_data);

    result.signature = signature;
    result.length = sig_len;
    return result;
}

// Function to verify a received signature
int verify_signature(const char *file_path, const char *pub_key_path, const unsigned char *signature, size_t sig_len)
{
    size_t file_len;
    unsigned char *file_data = read_file(file_path, &file_len);
    if (!file_data)
    {
        return 1;
    }

    FILE *key_file = fopen(pub_key_path, "r");
    if (!key_file)
    {
        perror("Error opening public key file");
        free(file_data);
        return 1;
    }

    EVP_PKEY *pub_key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!pub_key)
    {
        ERR_print_errors_fp(stderr);
        free(file_data);
        return 1;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        perror("EVP_MD_CTX_new failed");
        EVP_PKEY_free(pub_key);
        free(file_data);
        return 1;
    }

    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pub_key) != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pub_key);
        free(file_data);
        return 1;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, file_data, file_len) != 1)
    {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pub_key);
        free(file_data);
        return 1;
    }

    int result = EVP_DigestVerifyFinal(md_ctx, signature, sig_len);
    if (result == 1)
    {
        printf("Signature is valid.\n");
    }
    else
    {
        printf("Signature is INVALID.\n");
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pub_key);
    free(file_data);
    return result == 1 ? 0 : 1;
}

// Free allocated memory for signature
void free_signature(Signature *sig)
{
    if (sig && sig->signature)
    {
        free(sig->signature);
        sig->signature = NULL;
        sig->length = 0;
    }
}

// Generate Spines Internal Public Key (RSA-2048)
char *generate_spines_internal_public_key()
{
    EVP_PKEY *key = generate_rsa_key(2048);
    if (!key)
        return NULL;

    char *pub_key = get_public_key(key);
    free_rsa_key(key);
    return pub_key;
}

// Generate Spines Internal Private Key (Encrypted RSA-2048)
char *generate_spines_internal_private_key()
{
    EVP_PKEY *key = generate_rsa_key(2048);
    if (!key)
        return NULL;

    // assuming using a passphrase, NEED TO ASK
    // i dont think a passphrase is right for this, should i use an existing key ?
    char *passphrase = "passphrase";
    char *enc_priv_key = get_encrypted_private_key(key, passphrase);
    free_rsa_key(key);
    return enc_priv_key;
}

// Generate Spines External Public Key (Same as Internal)
char *generate_spines_external_public_key()
{
    return generate_spines_internal_public_key();
}

// Generate Spines External Private Key (Same as Internal)
char *generate_spines_external_private_key()
{
    return generate_spines_internal_private_key();
}

// Generate TPM Public Key (RSA-3072)
char *generate_tpm_public_key()
{
    EVP_PKEY *key = generate_rsa_key(3072);
    if (!key)
        return NULL;

    char *pub_key = get_public_key(key);
    free_rsa_key(key);
    return pub_key;
}

// Generate Instance Public Key (RSA-2048)
char *generate_instance_public_key()
{
    EVP_PKEY *key = generate_rsa_key(2048);
    if (!key)
        return NULL;

    char *pub_key = get_public_key(key);
    free_rsa_key(key);
    return pub_key;
}

// Generate Instance Private Key (RSA-2048, Encrypted)
char *generate_instance_private_key()
{
    EVP_PKEY *key = generate_rsa_key(2048);
    if (!key)
        return NULL;

    char *passphrase = "instance_passphrase";
    char *enc_priv_key = get_encrypted_private_key(key, passphrase);
    free_rsa_key(key);
    return enc_priv_key;
}

// Generate Prime Threshold Key Share (RSA-2048, Encrypted)
char *generate_prime_threshold_key_share()
{
    return generate_instance_private_key();
}

// Generate SM Threshold Key Share (Same as Prime Threshold)
char *generate_sm_threshold_key_share()
{
    return generate_instance_private_key();
}