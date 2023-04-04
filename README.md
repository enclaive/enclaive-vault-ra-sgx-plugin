# Vault SGX Plugin

Login to vault using SGX attestation.

## Usage

Read the `Makefile` to understand the usage. Here's the quickstart:

```bash
# Build plugin and start Vault dev server with plugin automatically registered
make
```

Now open a new terminal window and run the following commands:

```bash
# Enable the plugin
make enable

# Create a new enclave with a policy and secrets
make create

# Login using an attestation
make login
```
