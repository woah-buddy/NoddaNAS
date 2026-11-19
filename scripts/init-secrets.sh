#!/bin/sh
# Generates the secrets docker compose needs, with tight permissions.
# Run from deploy/compose. Existing secrets are never overwritten.
#
# There is no content-encryption key to generate: files are end-to-end
# encrypted by users' clients, and only they hold the keys.
set -eu
umask 077
dir=secrets
mkdir -p "$dir"

rand() { openssl rand -base64 "$1" | tr -d '\n'; }

if [ ! -f "$dir/postgres_password" ]; then
	rand 32 | tr '+/' '-_' > "$dir/postgres_password"
	echo "created $dir/postgres_password"
fi
if [ ! -f "$dir/database_url" ]; then
	printf 'postgres://noddanas:%s@postgres:5432/noddanas?sslmode=disable\n' "$(cat "$dir/postgres_password")" > "$dir/database_url"
	echo "created $dir/database_url"
fi
if [ ! -f "$dir/oidc_client_secret" ]; then
	: > "$dir/oidc_client_secret"
	echo "created empty $dir/oidc_client_secret  <- paste your OIDC client secret into it (leave empty if you use SAML only)"
fi

chmod 0400 "$dir"/*
# The NoddaNAS container runs as UID/GID 65532: hand its secrets to that user.
if [ "$(id -u)" = 0 ]; then
	chown 65532:65532 "$dir"/database_url "$dir"/oidc_client_secret
	chown 70:70 "$dir"/postgres_password 2>/dev/null || true # postgres (alpine) user
else
	echo "note: run 'sudo chown 65532:65532 $dir/database_url $dir/oidc_client_secret'"
	echo "      and 'sudo chown 70:70 $dir/postgres_password' so the containers can read them."
fi
