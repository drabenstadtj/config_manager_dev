#include <stdlib.h>
#include <stdio.h>
#include "parser.h"
#include "key_generation.h"

void generate_host_keys(struct host *host) {
    host->spines_internal_public_key = generate_spines_internal_public_key();
    host->encrypted_spines_internal_private_key = generate_spines_internal_private_key();
    host->spines_external_public_key = generate_spines_external_public_key();
    host->encrypted_spines_external_private_key = generate_spines_external_private_key();
}

void generate_replica_keys(struct replica *replica) {
    replica->tpm_public_key = generate_tpm_public_key();
    replica->instance_public_key = generate_instance_public_key();
    replica->encrypted_instance_private_key = generate_instance_private_key();
    replica->encrypted_prime_threshold_key_share = generate_prime_threshold_key_share();
    replica->encrypted_sm_threshold_key_share = generate_sm_threshold_key_share();
}

void generate_keys(struct config *cfg) {

    for (unsigned i = 0; i < cfg->sites_count; i++) {
        struct site *site = &cfg->sites[i];
        
        printf("Generating keys for site %s...\n", site->name);

        for (unsigned j = 0; j < site->hosts_count; j++) {
            
            generate_host_keys(&site->hosts[j]);
            printf("  Generated keys for host %s.\n", site->hosts[j].name);
        }
        
        for (unsigned j = 0; j < site->replicas_count; j++) {
            generate_replica_keys(&site->replicas[j]);\
            printf("  Generated keys for replica %d.\n", site->replicas[j].instance_id);
        }
    }

    printf("Key generation complete\n");
}


int main(int argc, char *argv[]) {
    // Check arguments
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_yaml> <output_yaml>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Load Arguments
    const char *input_yaml = argv[1];
    const char *output_yaml = argv[2];

    struct config *cfg = load_yaml_config(input_yaml);
    if (!cfg) {
        fprintf(stderr, "Failed to load configuration from %s\n", input_yaml);
        return EXIT_FAILURE;
    }

    generate_keys(cfg);

    // generate topology

    // for debuggin
    print_config(cfg);

    if (save_yaml_config(output_yaml, cfg) != 0) {
        fprintf(stderr, "Failed to save updated configuration to %s\n", output_yaml);
        free_yaml_config(&cfg);
        return EXIT_FAILURE;
    }   

    printf("Successfully generated keys and topology. Updated config saved to: %s\n", output_yaml);
    free_yaml_config(&cfg);
    return EXIT_SUCCESS;
}
