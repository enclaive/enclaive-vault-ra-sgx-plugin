#!/usr/bin/bash

set -eu

[[ -z "${APIKEY:-}" ]] && echo "APIKEY was not set" && exit 1

export HASH_USER=$( head /dev/random | sha512sum | awk '{print $1;}')
export HASH_ADMIN=$(head /dev/random | sha512sum | awk '{print $1;}')

jq '.ApiKey = $ENV.APIKEY | .UserTokenHash = $ENV.HASH_USER | .AdminTokenHash = $ENV.HASH_ADMIN' config/template.json \
  > config/default.json

/usr/bin/node pccs_server.js