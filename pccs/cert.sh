mkdir -p ssl_key
cd ssl_key
openssl genrsa -out private.pem 4096
openssl req -new -key private.pem -out csr.pem
openssl x509 -req -days 365 -in csr.pem -signkey private.pem -out file.crt
rm -rf csr.pem
chmod 644 private.pem
chmod 644 file.crt