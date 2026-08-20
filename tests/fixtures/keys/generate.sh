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

# --- A vector set, not a single signature ---------------------------------
#
# One key and one message per scheme is what this file used to hold, and it is
# the weakness NIST's CAVP SigVer sets exist to remove: a verifier can be
# wrong for whole classes of operand and still verify one signature. The two
# classes that matter for a hand-written implementation are ECDSA's DER
# integer encoding -- r or s with its top bit set needs a leading 0x00, and
# one shorter than 32 bytes has leading zeros stripped -- and RSA's varying
# message digests.
#
# CAVP's own files are not vendored here (they are large, and their licence
# and provenance would need tracking); instead the same coverage is produced
# locally and, crucially, the ECDSA vectors are BINNED by encoded r/s length
# so the awkward encodings are present by construction rather than by luck.
mkdir -p vectors
rm -f vectors/*.bin vectors/*.der vectors/manifest.txt

openssl genrsa -out "$WORK/rsa_v.pem" 2048 2>/dev/null
openssl rsa -in "$WORK/rsa_v.pem" -pubout -outform DER -out vectors/rsa2048.spki.der 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/p256_v.pem" 2>/dev/null
openssl ec -in "$WORK/p256_v.pem" -pubout -outform DER -out vectors/p256.spki.der 2>/dev/null

seen_short=0
seen_high=0
i=0
n=0
while [ "$n" -lt 24 ] && [ "$i" -lt 400 ]; do
    i=$((i + 1))
    printf 'tamga-c signature vector %d' "$i" > "$WORK/msg"

    openssl dgst -sha256 -sign "$WORK/rsa_v.pem" -out "$WORK/pkcs1" "$WORK/msg"
    openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
        -sign "$WORK/rsa_v.pem" -out "$WORK/pss" "$WORK/msg"
    openssl dgst -sha256 -sign "$WORK/p256_v.pem" -out "$WORK/ec" "$WORK/msg"

    # Classify the ECDSA signature by its DER integer lengths. A 33-byte
    # INTEGER carries the leading 0x00 a high top bit forces; anything under
    # 32 had leading zeros stripped.
    # Splitting on "l=" also matches the "hl=" on the same line, so the
    # length is pulled out positionally instead.
    lens=$(openssl asn1parse -inform DER -in "$WORK/ec" 2>/dev/null \
           | sed -n 's/.*hl=[0-9]* l= *\([0-9]*\).*INTEGER.*/\1/p' | tr '\n' ' ')
    keep=0
    case " $lens" in
        *" 33 "*) [ "$seen_high" -lt 6 ] && { seen_high=$((seen_high + 1)); keep=1; } ;;
    esac
    case " $lens" in
        *" 31 "*|*" 30 "*|*" 29 "*) [ "$seen_short" -lt 4 ] && { seen_short=$((seen_short + 1)); keep=1; } ;;
    esac
    [ "$n" -lt 12 ] && keep=1

    if [ "$keep" = 1 ]; then
        n=$((n + 1))
        cp "$WORK/msg"   "vectors/msg_$n.bin"
        cp "$WORK/pkcs1" "vectors/pkcs1_$n.bin"
        cp "$WORK/pss"   "vectors/pss_$n.bin"
        cp "$WORK/ec"    "vectors/ecdsa_$n.bin"
        echo "$n r/s DER lengths: $lens" >> vectors/manifest.txt
    fi
done
echo "count=$n" >> vectors/manifest.txt
echo "ecdsa vectors: $n (with a 33-byte INTEGER: $seen_high, with a short INTEGER: $seen_short)"
