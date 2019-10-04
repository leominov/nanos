#!/usr/bin/env bash
set -euo pipefail

echo "Starting Vault Server..."
docker rm -f dev-vault &> /dev/null || :
docker run --cap-add=IPC_LOCK -d --name=dev-vault -e 'VAULT_DEV_ROOT_TOKEN_ID=faketoken' -p 8200:8200 vault:1.1.2 &> /dev/null
echo "...done. Run \"docker rm -f dev-vault\" to clean up the container."
echo
