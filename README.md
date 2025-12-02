# Simple certificate generator

# Example usage
```
# Generate root CA
cargo r -- self-signed-ca --san root-ca --ttl=1y root-ca

# Generate intermediate CA
cargo r -- signed-cert --ca root-ca.pem --ca-key root-ca.key --san int-ca --is-ca --ttl 1M int-ca

# Generate certificate
cargo r -- signed-cert --ca int-ca.pem --ca-key int-ca.key --san server --ttl 1w server
```
