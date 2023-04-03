# Vault SGX Plugin


login to vault using sgx attestation.


## Usage



read the Makefile the understand usage. here's the quickstart:

```
# Build plugin and start Vault dev server with plugin automatically registered
make
```

Now open a new terminal window and run the following commands:

```

# Enable the plugin
make enable

# Create a new enclave
make create

# Login using an attestation
make login
```
