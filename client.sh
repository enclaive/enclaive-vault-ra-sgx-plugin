#!/usr/bin/bash

set -eu

COMMAND="$1"
shift

set -xo pipefail

export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_CACERT="${VAULT_CACERT:-certs/vault-ca.pem}"

NAME="redis"
MEASUREMENT="1b84298bc789748debbbb25db76a0bf85c983be4a9810ee734fd8aa3d3274f01"
ATTESTATION="yolo"
SECRET='{"environment": {}, "files": {"/dev/attestation/keys/data":"c1ydwRokay1R4xZ3mPwd1w==","/dev/attestation/keys/logs":"nKz4dRYLWQBhkW9bzs6HQw=="}, "argv": []}'

KEY_TYPE="ec"
KEY_BITS="256"

if [[ -f deployment.id ]]
then
  DEPLOYMENT_DOMAIN="$(cat deployment.id).enclaive"
fi

function setup() {
  if [[ ! -f deployment.id ]]
  then
    python -c 'import uuid; print(str(uuid.uuid4()).split("-")[0])' > deployment.id
  fi
}

function enable() {
  vault secrets enable \
    -path=sgx-app kv-v2 \
    || echo "Already enabled kvv2 at sgx-app"

  vault auth enable \
    -path=sgx-auth vault-plugin-auth-sgx \
    || echo "Already enabled sgx-auth"

  vault secrets enable \
    -path=sgx-pki-root pki \
    || echo "Already enabled sgx-pki-root"
  vault secrets enable \
    -path=sgx-pki pki \
    || echo "Already enabled sgx-pki"

  VAULT_DOMAIN="vault.${DEPLOYMENT_DOMAIN}"

  # configure ca
  vault write -format=json \
    sgx-pki-root/config/urls \
    issuing_certificates="https://${VAULT_DOMAIN}/v1/sgx-pki-root/ca" \
    crl_distribution_points="https://${VAULT_DOMAIN}/v1/sgx-pki-root/crl"
  vault write -format=json \
    sgx-pki/config/urls \
    issuing_certificates="https://${VAULT_DOMAIN}/v1/sgx-pki/ca" \
    crl_distribution_points="https://${VAULT_DOMAIN}/v1/sgx-pki/crl"

  # allow higher ttl
  vault secrets tune \
    -max-lease-ttl=87600h sgx-pki-root
  vault secrets tune \
    -max-lease-ttl=43800h sgx-pki

  # generate ca
  vault write -format=json \
    sgx-pki-root/root/generate/internal \
    ttl=87600h \
    key_type="${KEY_TYPE}" \
    key_bits="${KEY_BITS}" \
    common_name="${VAULT_DOMAIN} Root Authority"
  vault write -format=json \
    sgx-pki/intermediate/generate/internal \
    ttl=43800h \
    key_type="${KEY_TYPE}" \
    key_bits="${KEY_BITS}" \
    common_name="${VAULT_DOMAIN} Intermediate Authority" \
    | tee /dev/stderr \
    | jq -r '.data.csr' > certs/sgx-ca-intermediate.csr
  vault write -format=json \
    sgx-pki-root/root/sign-intermediate \
    csr=@certs/sgx-ca-intermediate.csr \
    format=pem_bundle \
    ttl=43800h \
    | tee /dev/stderr \
    | jq -r '.data.certificate' > certs/sgx-ca.pem
  vault write -format=json \
    sgx-pki/intermediate/set-signed \
    certificate=@certs/sgx-ca.pem
  rm certs/sgx-ca-intermediate.csr

  # generate external client cert
  vault write -format=json \
    sgx-pki/roles/"admin.client.${DEPLOYMENT_DOMAIN}" \
    allowed_domains="admin.client.${DEPLOYMENT_DOMAIN}" \
    allow_bare_domains=true \
    allow_subdomains=false \
    allow_localhost=false \
    ttl=8760h \
    key_type="${KEY_TYPE}" \
    key_bits="${KEY_BITS}"

  vault write -format=json \
    sgx-pki/issue/"admin.client.${DEPLOYMENT_DOMAIN}" \
    common_name="admin.client.${DEPLOYMENT_DOMAIN}" \
    | jq '.data' \
    > certs/sgx-client.json

  jq -r '.certificate' certs/sgx-client.json > certs/sgx-cert.pem
  jq -r '.private_key' certs/sgx-client.json > certs/sgx-key.pem
  chmod 0600 certs/sgx-key.pem
  rm certs/sgx-client.json
}

function create() {
  # register enclave
  vault write -format=json \
    auth/sgx-auth/enclave/"${NAME}" mrenclave="${MEASUREMENT}"

  # store secret
  vault kv put -format=json \
    -mount=sgx-app "${NAME}" provision="${SECRET}"

  # also could use NAME to be less specific
  APP_DOMAIN="${MEASUREMENT:0:32}.app.${DEPLOYMENT_DOMAIN}"

  # create a pki role
  vault write -format=json \
    sgx-pki/roles/"${APP_DOMAIN}" \
    allowed_domains="${APP_DOMAIN}" \
    allow_bare_domains=true \
    allow_subdomains=true \
    allow_localhost=false \
    ttl=8760h \
    key_type="${KEY_TYPE}" \
    key_bits="${KEY_BITS}"

  # allow access to secret and cert issuing
  vault policy write \
    sgx-app/"${NAME}" - \
    < <(env -i NAME="${NAME}" ROLE="${APP_DOMAIN}" envsubst < vault.sgx.policy.template)
}

function login() {
  vault write -format=json \
		-client-key=certs/vault-key.pem \
		-client-cert=certs/vault-cert.pem \
		auth/sgx-auth/login id="${NAME}" attestation="${ATTESTATION}"
}

case "${COMMAND}" in
  setup)  setup ;;
  enable) enable ;;
  create) create ;;
  login)  login ;;
  *)
    echo "Unknown command: ${COMMAND}"
    exit 1
    ;;
esac