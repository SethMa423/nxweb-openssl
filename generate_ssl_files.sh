#!/bin/bash

# This script generates files required for SSL operation of NXWEB.
# Their paths are defined in config.h (relative to work_dir):
#   define SSL_CERT_FILE "ssl/server_cert.pem"
#   define SSL_KEY_FILE "ssl/server_key.pem"

# Make sure openssl bin folder is in PATH
# OpenSSL v.3.0.0+ is strongly recommended

#OPENSSL_BIN_DIR=/usr/bin/
CA_CFG=ssl/ca.cfg
CA_KEY=ssl/ca_key.pem
CA_CERT=ssl/ca_cert.pem

SERVER_CFG=ssl/server.cfg
SERVER_KEY=ssl/server_key.pem
SERVER_CERT=ssl/server_cert.pem

# create test directory
if [ -d "ssl" ]; then
  rm -rf ssl/
fi

mkdir ssl/
cp sample_config/ssl/ca.cfg sample_config/ssl/server.cfg ssl/

# Generate self-signed certificate for certificate authority, 
# that shall sign other certificates
openssl genpkey -algorithm RSA -out $CA_KEY -pkeyopt rsa_keygen_bits:2048 -quiet

expect -c "
  spawn openssl req -new -x509 -key $CA_KEY -out $CA_CERT -config $CA_CFG
  expect \"C \"
  send \"\r\"
  expect \"O \"
  send \"\r\"
  expect \"CN \"
  send \"\r\"
  interact
"

# Create private key (RSA by default)
openssl genpkey -algorithm RSA -out $SERVER_KEY -pkeyopt rsa_keygen_bits:2048 -quiet

expect -c "
  spawn openssl req -CA $CA_CERT -CAkey $CA_KEY -key $SERVER_KEY -out $SERVER_CERT -config $SERVER_CFG
  expect \"C \"
  send \"\r\"
  expect \"ST \"
  send \"\r\"
  expect \"L \"
  send \"\r\"
  expect \"O \"
  send \"\r\"
  expect \"CN \"
  send \"\r\"
  interact
"