#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "parser.h"
#include "key_generation.h"

#define TMP_KEY_DIR "tpm_keys/"

// First pass: Generate a simulated TPM key for the host
void generate_simulated_tpm_key_for_host(struct host *host)
{
    char private_key_filepath[256];
    snprintf(private_key_filepath, sizeof(private_key_filepath), "%s%s_tpm_private.pem", TMP_KEY_DIR, host->name);

    // Generate RSA key for TPM simulation
    EVP_PKEY *tpm_key = generate_rsa_key(3072);
    if (!tpm_key)
    {
        fprintf(stderr, "Error: Failed to generate simulated TPM key for host %s\n", host->name);
        return;
    }

    // Extract private key in PEM format (unencrypted)
    char *tpm_private = get_private_key(tpm_key);
    if (!tpm_private)
    {
        fprintf(stderr, "Error: Failed to extract TPM private key for host %s\n", host->name);
        free_rsa_key(tpm_key);
        return;
    }

    // Write private key to file
    if (write_key_to_file(private_key_filepath, tpm_private) != 0)
    {
        fprintf(stderr, "Error: Failed to write TPM private key to %s\n", private_key_filepath);
        free(tpm_private);
        free_rsa_key(tpm_key);
        return;
    }

    // Save the private key location in the config
    host->permanent_key_location = strdup(private_key_filepath);

    // Extract and store the public key in config **after successfully writing private key**
    char *tpm_public = get_public_key(tpm_key);
    if (!tpm_public)
    {
        fprintf(stderr, "Error: Failed to extract TPM public key for host %s\n", host->name);
        free(tpm_private);
        free_rsa_key(tpm_key);
        return;
    }

    host->permanent_public_key = tpm_public;

    printf("Simulated TPM key generated for host %s\n", host->name);

    // Cleanup
    free(tpm_private);
    free_rsa_key(tpm_key);
}

// Second pass: Generate all keys using the permanent public key
void generate_keys_for_host(struct host *host)
{
    if (!host->permanent_public_key)
    {
        fprintf(stderr, "Error: TPM public key missing for host %s\n", host->name);
        return;
    }

    host->spines_internal_public_key = generate_spines_internal_public_key();
    host->encrypted_spines_internal_private_key = get_encrypted_private_key(
        generate_rsa_key(2048), host->permanent_public_key);

    host->spines_external_public_key = generate_spines_external_public_key();
    host->encrypted_spines_external_private_key = get_encrypted_private_key(
        generate_rsa_key(2048), host->permanent_public_key);

    printf("Host %s: Encrypted private keys using permanent TPM public key.\n", host->name);
}

// Generate keys for replicas (use host's TPM public key)
void generate_keys_for_replica(struct replica *replica, struct host *host)
{
    if (!host->permanent_public_key)
    {
        fprintf(stderr, "Error: TPM public key missing for host %s (replica %d)\n", host->name, replica->instance_id);
        return;
    }

    replica->instance_public_key = generate_instance_public_key();
    replica->encrypted_instance_private_key = get_encrypted_private_key(
        generate_rsa_key(2048), host->permanent_public_key);

    replica->encrypted_prime_threshold_key_share = get_encrypted_private_key(
        generate_rsa_key(2048), host->permanent_public_key);

    replica->encrypted_sm_threshold_key_share = get_encrypted_private_key(
        generate_rsa_key(2048), host->permanent_public_key);

    printf("Replica %d (Host: %s): Encrypted private keys using permanent TPM public key.\n", replica->instance_id, host->name);
}

// Find the host associated with a given replica
struct host *find_host_for_replica(struct site *site, const char *host_name)
{
    for (unsigned j = 0; j < site->hosts_count; j++)
    {
        if (strcmp(site->hosts[j].name, host_name) == 0)
        {
            return &site->hosts[j];
        }
    }
    return NULL; // No matching host found (shouldn't happen if the config is correct)
}

void first_pass_generate_tpm_keys(struct config *cfg)
{
    printf("Starting first pass: Generating simulated TPM keys...\n");
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];

        for (unsigned j = 0; j < site->hosts_count; j++)
        {
            generate_simulated_tpm_key_for_host(&site->hosts[j]);
        }
    }
    printf("First pass complete.\n");
}

void second_pass_generate_keys(struct config *cfg)
{
    printf("Starting second pass: Generating all other keys...\n");
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *site = &cfg->sites[i];

        for (unsigned j = 0; j < site->hosts_count; j++)
        {
            generate_keys_for_host(&site->hosts[j]);
        }

        for (unsigned j = 0; j < site->replicas_count; j++)
        {
            struct replica *replica = &site->replicas[j];
            struct host *replica_host = find_host_for_replica(site, replica->host);

            if (replica_host)
            {
                generate_keys_for_replica(replica, replica_host);
            }
            else
            {
                fprintf(stderr, "Error: Replica %d has no matching host %s!\n", replica->instance_id, replica->host);
            }
        }
    }
    printf("Second pass complete.\n");
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <input_yaml> <output_yaml>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Load Configuration
    const char *input_yaml = argv[1];
    const char *output_yaml = argv[2];

    struct config *cfg = load_yaml_config(input_yaml);
    if (!cfg)
    {
        fprintf(stderr, "Failed to load configuration from %s\n", input_yaml);
        return EXIT_FAILURE;
    }

    // First pass: Generate simulated TPM keys
    first_pass_generate_tpm_keys(cfg);

    // Second pass: Generate and encrypt the rest of the keys
    second_pass_generate_keys(cfg);

    // Debugging output
    print_config(cfg);

    if (save_yaml_config(output_yaml, cfg) != 0)
    {
        fprintf(stderr, "Failed to save updated configuration to %s\n", output_yaml);
        free_yaml_config(&cfg);
        return EXIT_FAILURE;
    }

    printf("Successfully generated keys and topology. Updated config saved to: %s\n", output_yaml);

    free_yaml_config(&cfg);
    return EXIT_SUCCESS;
}

// int main(int argc, char *argv[]) {
//     // Check arguments
//     if (argc != 3) {
//         fprintf(stderr, "Usage: %s <input_yaml> <output_yaml>\n", argv[0]);
//         return EXIT_FAILURE;
//     }

//     // Load Arguments
//     const char *input_yaml = argv[1];
//     const char *output_yaml = argv[2];

//     struct config *cfg = load_yaml_config(input_yaml);
//     if (!cfg) {
//         fprintf(stderr, "Failed to load configuration from %s\n", input_yaml);
//         return EXIT_FAILURE;
//     }

//      // First pass: Generate simulated TPM keys
//      first_pass_generate_tpm_keys(cfg);

//      // Second pass: Generate and encrypt the rest of the keys
//      second_pass_generate_keys(cfg);

//     // generate topology
//     generate_topology(cfg);

//     // for debuggin
//     print_config(cfg);

//     if (save_yaml_config(output_yaml, cfg) != 0) {
//         fprintf(stderr, "Failed to save updated configuration to %s\n", output_yaml);
//         free_yaml_config(&cfg);
//         return EXIT_FAILURE;
//     }

//     printf("Successfully generated keys and topology. Updated config saved to: %s\n", output_yaml);
//     free_yaml_config(&cfg);
//     return EXIT_SUCCESS;
// }
