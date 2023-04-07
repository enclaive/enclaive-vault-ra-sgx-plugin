ui = true

storage "file" {
    path = "/data"
}

listener "tcp" {
    address = "0.0.0.0:8200"
    tls_cert_file = "/secrets/tmp/cert.pem"
    tls_key_file = "/secrets/tmp/key.pem"
}

plugin_directory = "/app/plugins/"