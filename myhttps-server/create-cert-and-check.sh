#!/usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# https://stackoverflow.com/a/27724156
# diff  /usr/local/etc/openssl/openssl.cnf openssl.cnf > openssl.cnf.diff
# https://support.apple.com/en-us/HT210176

# 1
# openssl genrsa -out private.key 3072
openssl req -new -x509 -key ${SCRIPT_DIR}/private.key -sha256 -out ${SCRIPT_DIR}/certificate.pem -days 730 -config ${SCRIPT_DIR}/openssl.cnf
openssl x509 -in ${SCRIPT_DIR}/certificate.pem -text -noout | grep DNS

openssl x509 -outform der -in ${SCRIPT_DIR}/certificate.pem -out ${SCRIPT_DIR}/ca.der

security verify-cert -c ${SCRIPT_DIR}/certificate.pem -r  ${SCRIPT_DIR}/certificate.pem -p ssl -v
