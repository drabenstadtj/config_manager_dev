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
    CYAML_FIELD_STRING_PTR("permanent_public_key", CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL, struct host, permanent_public_key, 0, CYAML_UNLIMITED),
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
    CYAML_FIELD_STRING_PTR("name", CYAML_FLAG_POINTER, struct topology_host, name, 0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT("id", CYAML_FLAG_DEFAULT, struct topology_host, id),
    CYAML_FIELD_END};

static const cyaml_schema_value_t topology_host_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct topology_host, topology_host_schema_fields),
};

static const cyaml_schema_field_t topology_edge_schema_fields[] = {
    CYAML_FIELD_UINT("id1", CYAML_FLAG_DEFAULT, struct topology_edge, id1),
    CYAML_FIELD_UINT("id2", CYAML_FLAG_DEFAULT, struct topology_edge, id2),
    CYAML_FIELD_UINT("cost", CYAML_FLAG_DEFAULT, struct topology_edge, cost),
    CYAML_FIELD_END};

static const cyaml_schema_value_t topology_edge_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct topology_edge, topology_edge_schema_fields),
};

static const cyaml_schema_field_t spines_topology_schema_fields[] = {
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
    // .log_level = CYAML_LOG_DEBUG,
    .log_level = CYAML_LOG_WARNING,
    .log_fn = cyaml_log,
    .mem_fn = cyaml_mem,
};

// Helper Struct for generating topology data

struct topology_data
{
    struct topology_host *internal_hosts;
    int internal_host_count;

    struct topology_host *replicas;
    int replica_count;

    struct topology_host *clients;
    int client_count;
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
}

// Main function to generate Spines Topology
int generate_topology(struct config *cfg)
{
    if (!cfg)
    {
        fprintf(stderr, "Config structure is NULL\n");
        return -1;
    }
    printf("Generating topology...\n");

    // # spines_internal:
    // #   - This is a clique of all spines_internal_daemons
    // # spines_external:
    // #   - There is clique of all spines_external_daemons associated with replicas
    // #   - Each "replica" spines_external_daemon is connected to each "client" spines_external_daemon
    // #   - Note that client daemons are not connected to each other

    // SPINES INTERNAL

    // determine a list of all hosts with spines_internal_daemons: 1
    // containing host name and an id
    // generate a clique of all spines_internal_daemons

    // SPINES EXTERNAL
    // determine a list of all replicas with spines_external_daemons: 1
    // determine a list of clients
    // connect each replica to eachother in a clique
    // connnect each replica to each client
    // note: do not connect each client to each other

    // First, determine the counts of pertinent nodes
    unsigned internal_count = 0, replica_count = 0, client_count = 0;

    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *s = &cfg->sites[i];

        for (unsigned j = 0; j < s->hosts_count; j++)
        {
            if (s->hosts[j].runs_spines_internal)
            {
                internal_count++;
            }
            if (s->hosts[j].runs_spines_external && s->type == CLIENT)
            {
                client_count++;
            }
        }

        // not super sure if this is the correct check for the 'spines_external_daemons associated with replicas'
        for (unsigned j = 0; j < s->replicas_count; j++)
        {
            if (s->replicas[j].spines_external_daemon)
            {
                replica_count++;
            }
        }
    }

    // Allocate memory for internal topology
    cfg->spines_internal_topology = malloc(sizeof(struct spines_topology));
    if (!cfg->spines_internal_topology)
    {
        fprintf(stderr, "Memory allocation failed for internal topology\n");
        return -1;
    }

    cfg->spines_internal_topology->hosts_count = internal_count;
    cfg->spines_internal_topology->hosts = malloc(internal_count * sizeof(struct topology_host));
    cfg->spines_internal_topology->edges_count = (internal_count * (internal_count - 1)) / 2; // edge count of clique: N * (N - 1) / 2
    cfg->spines_internal_topology->edges = malloc(cfg->spines_internal_topology->edges_count * sizeof(struct topology_edge));

    if (!cfg->spines_internal_topology->hosts || !cfg->spines_internal_topology->edges)
    {
        fprintf(stderr, "Memory allocation failed for internal topology elements\n");
        return -1;
    }

    // Populate internal topology
    unsigned internal_idx = 0, edge_idx = 0;

    // generates the 'hosts'
    // for each site
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *s = &cfg->sites[i];

        // for each host
        for (unsigned j = 0; j < s->hosts_count; j++)
        {
            // if host runs spines internal
            if (s->hosts[j].runs_spines_internal)
            {
                // assign an id
                cfg->spines_internal_topology->hosts[internal_idx].id = internal_idx;
                // assign a name
                cfg->spines_internal_topology->hosts[internal_idx].name = strdup(s->hosts[j].name);
                internal_idx++;
            }
        }
    }

    // generates the 'edges'
    // for every host
    for (unsigned i = 0; i < internal_count; i++)
    {
        // for every host
        for (unsigned j = i + 1; j < internal_count; j++)
        {
            // create an edge between them
            cfg->spines_internal_topology->edges[edge_idx].id1 = i;
            cfg->spines_internal_topology->edges[edge_idx].id2 = j;
            cfg->spines_internal_topology->edges[edge_idx].cost = 1;
            edge_idx++;
        }
    }

    // Allocate memory for external topology
    cfg->spines_external_topology = malloc(sizeof(struct spines_topology));
    if (!cfg->spines_external_topology)
    {
        fprintf(stderr, "Memory allocation failed for external topology\n");
        return -1;
    }
    // memset(cfg->spines_external_topology, 0, sizeof(struct spines_topology));  // Initialize to avoid garbage values

    cfg->spines_external_topology->hosts_count = replica_count + client_count;
    cfg->spines_external_topology->hosts = malloc(cfg->spines_external_topology->hosts_count * sizeof(struct topology_host));
    cfg->spines_external_topology->edges_count = (replica_count * (replica_count - 1)) / 2 + (replica_count * client_count); // total replicas * (total replicas - 1) / 2 + total replicas * clients (clique amongst replicas, then all replicas to each client)
    cfg->spines_external_topology->edges = malloc(cfg->spines_external_topology->edges_count * sizeof(struct topology_edge));

    if (!cfg->spines_external_topology->hosts || !cfg->spines_external_topology->edges)
    {
        fprintf(stderr, "Memory allocation failed for external topology elements\n");
        return -1;
    }

    // Populate external topology
    unsigned replica_idx = 0, client_idx = replica_count, ext_edge_idx = 0;

    // for each site
    for (unsigned i = 0; i < cfg->sites_count; i++)
    {
        struct site *s = &cfg->sites[i];

        // for each replica
        for (unsigned j = 0; j < s->replicas_count; j++)
        {
            // if it has an external daemon
            if (s->replicas[j].spines_external_daemon)
            {
                // add it as a host
                cfg->spines_external_topology->hosts[replica_idx].id = replica_idx;
                cfg->spines_external_topology->hosts[replica_idx].name = strdup(s->replicas[j].spines_external_daemon);
                replica_idx++;
            }
        }

        // for each host
        for (unsigned j = 0; j < s->hosts_count; j++)
        {
            // if the host runs spines external and is a client
            if (s->hosts[j].runs_spines_external && s->type == CLIENT)
            {
                // add it as a host
                cfg->spines_external_topology->hosts[client_idx].id = client_idx;
                cfg->spines_external_topology->hosts[client_idx].name = strdup(s->hosts[j].name);
                client_idx++;
            }
        }
    }

    // connects each replica to each other replica
    // for each replica
    for (unsigned i = 0; i < replica_count; i++)
    {
        // for each replica
        for (unsigned j = i + 1; j < replica_count; j++)
        {
            // add an edge
            cfg->spines_external_topology->edges[ext_edge_idx].id1 = i;
            cfg->spines_external_topology->edges[ext_edge_idx].id2 = j;
            cfg->spines_external_topology->edges[ext_edge_idx].cost = 1;
            ext_edge_idx++;
        }
    }

    // Connect each replica to each client
    // for each replica
    for (unsigned i = 0; i < replica_count; i++)
    {
        // for each client
        for (unsigned j = 0; j < client_count; j++)
        {
            // add an edge
            cfg->spines_external_topology->edges[ext_edge_idx].id1 = i;
            cfg->spines_external_topology->edges[ext_edge_idx].id2 = replica_count + j;
            cfg->spines_external_topology->edges[ext_edge_idx].cost = 1;
            ext_edge_idx++;
        }
    }

    // DEBUG PRINT
    printf("Internal topology: hosts_count=%u, edges_count=%u\n",
           cfg->spines_internal_topology->hosts_count,
           cfg->spines_internal_topology->edges_count);

    // Print hosts
    for (unsigned i = 0; i < cfg->spines_internal_topology->hosts_count; i++)
    {
        printf("  Host %u: name=%s, id=%u\n",
               i, cfg->spines_internal_topology->hosts[i].name,
               cfg->spines_internal_topology->hosts[i].id);
    }

    // Print edges
    for (unsigned i = 0; i < cfg->spines_internal_topology->edges_count; i++)
    {
        printf("  Edge %u: id1=%u, id2=%u, cost=%u\n",
               i,
               cfg->spines_internal_topology->edges[i].id1,
               cfg->spines_internal_topology->edges[i].id2,
               cfg->spines_internal_topology->edges[i].cost);
    }

    // DEBUG PRINT
    printf("external topology: hosts_count=%u, edges_count=%u\n",
           cfg->spines_external_topology->hosts_count,
           cfg->spines_external_topology->edges_count);

    // Print hosts
    for (unsigned i = 0; i < cfg->spines_external_topology->hosts_count; i++)
    {
        printf("  Host %u: name=%s, id=%u\n",
               i, cfg->spines_external_topology->hosts[i].name,
               cfg->spines_external_topology->hosts[i].id);
    }

    // Print edges
    for (unsigned i = 0; i < cfg->spines_external_topology->edges_count; i++)
    {
        printf("  Edge %u: id1=%u, id2=%u, cost=%u\n",
               i,
               cfg->spines_external_topology->edges[i].id1,
               cfg->spines_external_topology->edges[i].id2,
               cfg->spines_external_topology->edges[i].cost);
    }

    printf("Topology generation complete.\n");
    return 0;
}

// int generate_internal_topology(struct config *cfg) {

// }

// int generate_external_topology(struct config *cfg) {

// }

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
