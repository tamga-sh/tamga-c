#!/bin/sh
# Regenerates the RSA/ECDSA key material and signatures the crypto tests
# verify against.
#
# The private keys are deliberately NOT committed: they exist only for the
# few seconds this script runs, and a repository that ships a private key --
# even a throwaway one -- trains both scanners and readers to ignore the
# thing they should never ignore. Everything the tests need is public: the
# SubjectPublicKeyInfo, the message, and the signatures.
#
# Regenerating produces different key material, which is fine. The tests read
# whatever is committed; nothing hardcodes these bytes.
#
# Usage: sh tests/fixtures/keys/generate.sh
set -e
cd "$(dirname "$0")"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

printf 'eyJkYXRhIjp7ImlkIjoiMSJ9fQ==' > message.txt

# --- RSA-2048 -------------------------------------------------------------
openssl genrsa -out "$WORK/rsa2048.pem" 2048 2>/dev/null
openssl rsa -in "$WORK/rsa2048.pem" -pubout -outform DER -out rsa2048.spki.der 2>/dev/null
openssl dgst -sha256 -sign "$WORK/rsa2048.pem" -out sig_pkcs1.bin message.txt
openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    -sign "$WORK/rsa2048.pem" -out sig_pss.bin message.txt

# --- ECDSA P-256 ----------------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/p256.pem" 2>/dev/null
openssl ec -in "$WORK/p256.pem" -pubout -outform DER -out p256.spki.der 2>/dev/null
openssl dgst -sha256 -sign "$WORK/p256.pem" -out sig_ecdsa.bin message.txt

# A secp256k1 key, used to build the curve-confusion regression fixture: its
# SPKI has the same shape and the same point length as the P-256 one, and
# differs only in the curve OID.
openssl ecparam -name secp256k1 -genkey -noout -out "$WORK/k256.pem" 2>/dev/null
openssl ec -in "$WORK/k256.pem" -pubout -outform DER -out secp256k1.spki.der 2>/dev/null

echo "Regenerated:"
ls -1 ./*.der ./*.bin message.txt
