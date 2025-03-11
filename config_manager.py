import yaml
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_pem, public_pem

def process_configuration(config):
    for site in config['sites']:
        for host in site['hosts']:
            if host.get('runs_spines_internal', 0):
                private_key, public_key = generate_rsa_keypair()
                host['spines_internal_public_key'] = public_key.strip()
                host['encrypted_spines_internal_private_key'] = private_key.strip()

            if host.get('runs_spines_external', 0):
                private_key, public_key = generate_rsa_keypair()
                host['spines_external_public_key'] = public_key.strip()
                host['encrypted_spines_external_private_key'] = private_key.strip()

    for site in config['sites']:
        if 'replicas' in site:
            for replica in site['replicas']:
                private_key, public_key = generate_rsa_keypair()
                replica['tpm_public_key'] = public_key.strip()
                replica['instance_public_key'] = public_key.strip()
                replica['encrypted_instance_private_key'] = private_key.strip()
                replica['encrypted_prime_threshold_key_share'] = 'XXXX'
                replica['encrypted_sm_threshold_key_share'] = 'XXXX'

    return config

def generate_topology(config):
    internal_hosts = []
    external_hosts = []
    for site in config['sites']:
        for host in site['hosts']:
            host_id = len(internal_hosts) + 1
            if host.get('runs_spines_internal', 0):
                internal_hosts.append({'name': host['name'], 'id': host_id})
            if host.get('runs_spines_external', 0):
                external_hosts.append({'name': host['name'], 'id': host_id})
    
    internal_edges = [{'id1': h1['id'], 'id2': h2['id'], 'cost': 100} for i, h1 in enumerate(internal_hosts) for h2 in internal_hosts[i+1:]]
    external_edges = [{'id1': h1['id'], 'id2': h2['id'], 'cost': 100} for i, h1 in enumerate(external_hosts) for h2 in external_hosts[i+1:]]
    
    config['spines_internal_topology'] = {'hosts': internal_hosts, 'edges': internal_edges}
    config['spines_external_topology'] = {'hosts': external_hosts, 'edges': external_edges}

    return config

def write_configuration(config, filename='output_configuration.yaml'):
    with open(filename, 'w') as file:
        yaml.dump(config, file, default_flow_style=False)
    print(f'Configuration written to {filename}')

def main():
    input_filename = 'pre_config.yaml'
    with open(input_filename, 'r') as file:
        config = yaml.safe_load(file)
    
    config = process_configuration(config)
    config = generate_topology(config)
    write_configuration(config)

if __name__ == '__main__':
    main()
