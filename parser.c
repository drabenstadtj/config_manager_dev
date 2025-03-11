#include <stdio.h>
#include <stdlib.h>
#include "parser.h"
#include <string.h>

/**
 * Host Schema Declaration
 */

static const cyaml_schema_field_t host_schema_fields[] = {
    CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER, struct host, name, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("ip", CYAML_FLAG_POINTER, struct host, ip, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("permanent_key_location", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct host, permanent_key_location, 0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT("runs_spines_internal", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct host, runs_spines_internal),
    CYAML_FIELD_UINT("runs_spines_external", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct host, runs_spines_external),
    // Future fields (currently required but can be empty for now)
    CYAML_FIELD_STRING_PTR("spines_internal_public_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct host, spines_internal_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("encrypted_spines_internal_private_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct host, encrypted_spines_internal_private_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("spines_external_public_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct host, spines_external_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("encrypted_spines_external_private_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct host, encrypted_spines_external_private_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t host_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct host, host_schema_fields),
};

/**
 * Replica Schema Declaration
 */

static const cyaml_schema_field_t replica_schema_fields[] = {
    CYAML_FIELD_UINT("instance_id", CYAML_FLAG_DEFAULT, struct replica, instance_id),
    CYAML_FIELD_STRING_PTR("host", CYAML_FLAG_POINTER, struct replica, host, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("spines_internal_daemon", CYAML_FLAG_POINTER, struct replica, spines_internal_daemon, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("spines_external_daemon", CYAML_FLAG_POINTER, struct replica, spines_external_daemon, 0, CYAML_UNLIMITED),
    // Future fields (currently required but can be empty initially)
    CYAML_FIELD_STRING_PTR("tpm_public_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct replica, tpm_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("instance_public_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct replica, instance_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("encrypted_instance_private_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct replica, encrypted_instance_private_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("encrypted_prime_threshold_key_share", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct replica, encrypted_prime_threshold_key_share, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("encrypted_sm_threshold_key_share", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct replica, encrypted_sm_threshold_key_share, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t replica_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct replica, replica_schema_fields),
};

/**
 * Site Schema Declaration
 */

static const cyaml_strval_t site_type_strings[] = {
    {"CONTROL_CENTER", CONTROL_CENTER},
    {"DATA_CENTER", DATA_CENTER},
    {"CLIENT", CLIENT},
};

static const cyaml_schema_field_t site_schema_fields[] = {
    CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER, struct site, name, 0, CYAML_UNLIMITED),
    CYAML_FIELD_ENUM("type", CYAML_FLAG_DEFAULT, struct site, type, site_type_strings, CYAML_ARRAY_LEN(site_type_strings)),
    CYAML_FIELD_SEQUENCE_COUNT("hosts", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct site, hosts, hosts_count, &host_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("replicas", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct site, replicas, replicas_count, &replica_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t site_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct site, site_schema_fields),
};

/**
 * Topology Schema Declaration
 */

static const cyaml_schema_field_t topology_host_schema_fields[] = {
    CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct topology_host, name, 0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT("id", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct topology_host, id),
    CYAML_FIELD_END};

static const cyaml_schema_value_t topology_host_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct topology_host, topology_host_schema_fields),
};

static const cyaml_schema_field_t topology_edge_schema_fields[] = {
    CYAML_FIELD_UINT("id1", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct topology_edge, id1),
    CYAML_FIELD_UINT("id2", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct topology_edge, id2),
    CYAML_FIELD_UINT("cost", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct topology_edge, cost),
    CYAML_FIELD_END};

static const cyaml_schema_value_t topology_edge_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct topology_edge, topology_edge_schema_fields),
};

static const cyaml_schema_field_t spines_topology_schema_fields[] = {
    // CYAML_FIELD_SEQUENCE_COUNT("hosts", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct spines_topology, hosts, hosts_count, &topology_host_schema, 0, CYAML_UNLIMITED),
    // CYAML_FIELD_SEQUENCE_COUNT("edges", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct spines_topology, edges, edges_count, &topology_edge_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("hosts", CYAML_FLAG_POINTER, struct spines_topology, hosts, hosts_count, &topology_host_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE_COUNT("edges", CYAML_FLAG_POINTER, struct spines_topology, edges, edges_count, &topology_edge_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

/**
 * Service Keys Schema Declaration
 */

static const cyaml_schema_field_t service_keys_schema_fields[] = {
    CYAML_FIELD_STRING_PTR("sm_threshold_public_key", CYAML_FLAG_POINTER, struct service_keys, sm_threshold_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("prime_threshold_public_key", CYAML_FLAG_POINTER, struct service_keys, prime_threshold_public_key, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

/**
 * Config Message Schema Declaration
 */

static const cyaml_schema_field_t config_schema_fields[] = {
    CYAML_FIELD_UINT("configuration_id", CYAML_FLAG_DEFAULT, struct config, configuration_id),
    CYAML_FIELD_UINT("tolerated_byzantine_faults", CYAML_FLAG_DEFAULT, struct config, tolerated_byzantine_faults),
    CYAML_FIELD_UINT("tolerated_unavailable_replicas", CYAML_FLAG_DEFAULT, struct config, tolerated_unavailable_replicas),
    CYAML_FIELD_MAPPING("service_keys", CYAML_FLAG_DEFAULT, struct config, service_keys, service_keys_schema_fields),
    CYAML_FIELD_SEQUENCE_COUNT("sites", CYAML_FLAG_POINTER, struct config, sites, sites_count, &site_schema, 0, CYAML_UNLIMITED),
    // CYAML_FIELD_MAPPING("spines_internal_topology", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct config, spines_internal_topology, spines_topology_schema_fields),
    // CYAML_FIELD_MAPPING("spines_external_topology", CYAML_FLAG_DEFAULT | CYAML_FLAG_OPTIONAL, struct config, spines_external_topology, spines_topology_schema_fields),
    CYAML_FIELD_END};

static const cyaml_schema_value_t config_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct config, config_schema_fields),
};

static const cyaml_config_t cyaml_config = {
    .log_level = CYAML_LOG_DEBUG,
    // .log_level = CYAML_LOG_WARNING,
    .log_fn = cyaml_log,
    .mem_fn = cyaml_mem,
};

// Function to load YAML config
struct config *load_yaml_config(const char *yaml_file)
{
    cyaml_err_t err;
    struct config *buff = NULL;

    printf("Loading YAML file: %s\n", yaml_file);

    err = cyaml_load_file(yaml_file, &cyaml_config, &config_schema, (cyaml_data_t **)&buff, NULL);

    if (err != CYAML_OK || buff == NULL)
    {
        fprintf(stderr, "Error loading YAML file '%s': %s\n", yaml_file, cyaml_strerror(err));
        return NULL;
    }

    printf("Successfully loaded YAML configuration.\n");

    return buff;
}

int save_yaml_config(const char *yaml_file, struct config *cfg)
{
    cyaml_err_t err;

    if (!yaml_file || !cfg)
    {
        fprintf(stderr, "Invalid arguments to save_yaml_config()\n");
        return -1;
    }

    printf("Saving YAML configuration to file: %s\n", yaml_file);

    err = cyaml_save_file(yaml_file, &cyaml_config, &config_schema, cfg, 0);
    if (err != CYAML_OK)
    {
        fprintf(stderr, "Error saving YAML file '%s': %s\n", yaml_file, cyaml_strerror(err));
        return -1;
    }

    printf("Successfully saved YAML configuration to %s\n", yaml_file);
    return 0;
}

void free_yaml_config(struct config **cfg)
{
    if (cfg == NULL || *cfg == NULL)
        return;

    printf("Freeing YAML configuration...\n");

    cyaml_err_t err = cyaml_free(&cyaml_config, &config_schema, *cfg, 0);
    if (err != CYAML_OK)
    {
        fprintf(stderr, "Failed to free YAML data: %s\n", cyaml_strerror(err));
    }
    else
    {
        printf("YAML configuration freed successfully.\n");
    }

    // Set to NULL regardless of success to prevent use-after-free
    *cfg = NULL;
}

// Main function to generate Spines Topology
int generate_topology(struct config *cfg)
{
    printf("Generating topology...\n");

    // CALL generate_spines_internal_topology(replicas) → spines_internal_topology
    // CALL generate_spines_external_topology(replicas, clients) → spines_external_topology

    printf("Topology generation complete.\n");
    return 0;
}

void print_service_keys(const struct service_keys *keys, int indent)
{
    if (!keys)
    {
        printf("%*sservice_keys: (NULL)\n", indent, "");
        return;
    }

    printf("%*sservice_keys:\n", indent, "");
    printf("%*s  sm_threshold_public_key: \"%s\"\n",
           indent, "", keys->sm_threshold_public_key ? keys->sm_threshold_public_key : "(NULL)");
    printf("%*s  prime_threshold_public_key: \"%s\"\n",
           indent, "", keys->prime_threshold_public_key ? keys->prime_threshold_public_key : "(NULL)");
}

void print_host(const struct host *h, int indent)
{
    if (!h)
        return;
    printf("%*s  - name: %s\n", indent, "", h->name);
    printf("%*s    ip: %s\n", indent, "", h->ip);
    if (h->permanent_key_location)
        printf("%*s    permanent_key_location: \"%s\"\n", indent, "", h->permanent_key_location);
    printf("%*s    runs_spines_internal: %u\n", indent, "", h->runs_spines_internal);
    printf("%*s    runs_spines_external: %u\n", indent, "", h->runs_spines_external);
}

void print_replica(const struct replica *r, int indent)
{
    if (!r)
        return;
    printf("%*s  - instance_id: %u\n", indent, "", r->instance_id);
    printf("%*s    host: %s\n", indent, "", r->host);
    printf("%*s    spines_internal_daemon: %s\n", indent, "", r->spines_internal_daemon);
    printf("%*s    spines_external_daemon: %s\n", indent, "", r->spines_external_daemon);
}

void print_site(const struct site *s, int indent)
{
    if (!s)
        return;
    printf("%*s- name: %s\n", indent, "", s->name);
    printf("%*s  type: %s\n", indent, "", s->type == CONTROL_CENTER ? "CONTROL_CENTER" : "CLIENT");

    if (s->hosts_count > 0)
    {
        printf("%*s  hosts:\n", indent, "");
        for (unsigned i = 0; i < s->hosts_count; i++)
        {
            print_host(&s->hosts[i], indent + 2);
        }
    }

    if (s->replicas_count > 0)
    {
        printf("%*s  replicas:\n", indent, "");
        for (unsigned i = 0; i < s->replicas_count; i++)
        {
            print_replica(&s->replicas[i], indent + 2);
        }
    }
}

void print_config(const struct config *cfg)
{
    if (!cfg)
        return;

    printf("configuration_id: %u\n", cfg->configuration_id);
    printf("tolerated_byzantine_faults: %u\n", cfg->tolerated_byzantine_faults);
    printf("tolerated_unavailable_replicas: %u\n", cfg->tolerated_unavailable_replicas);

    print_service_keys(&cfg->service_keys, 0);

    printf("sites:\n");
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        print_site(&cfg->sites[i], 2);
    }
}
