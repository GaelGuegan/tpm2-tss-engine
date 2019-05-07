#!/bin/bash

set -eufx

DIR=$(mktemp -d)

# Create an Primary key pair
echo "Generating primary key"
PARENT_CTX=${DIR}/primary_owner_key.ctx

tpm2_startup -c || true

tpm2_createprimary -a o -g sha256 -G rsa -o ${PARENT_CTX}
tpm2_flushcontext -t

# Create an Sym key
echo "Generating SYM key"
TPM_RSA_PUBKEY=${DIR}/rsakey.pub
TPM_RSA_KEY=${DIR}/rsakey
ALGO="aes"
tpm2_create -C ${PARENT_CTX} -g sha256 -G ${ALGO} -u ${TPM_RSA_PUBKEY} -r ${TPM_RSA_KEY} -b  sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth
tpm2_flushcontext -t

# Load Key to persistent handle
RSA_CTX=${DIR}/rsakey.ctx
tpm2_load -C ${PARENT_CTX} -u ${TPM_RSA_PUBKEY} -r ${TPM_RSA_KEY} -o ${RSA_CTX}
tpm2_flushcontext -t

HANDLE=$(tpm2_evictcontrol -a o -c ${RSA_CTX} | cut -d ' ' -f 2)
tpm2_flushcontext -t

KEY=$(echo ${HANDLE} | cut -d 'x' -f 2)
IV="0123456789012345"
if openssl version | grep "OpenSSL 1.0.2" > /dev/null; then
    echo -n "hello" > ${DIR}/data.txt
else
    echo -n "hello world goodbye world tpm2 tss openssl" > ${DIR}/data.txt
fi

# Encrypt, Decrypt, Diff Data
openssl enc -aes-256-cfb -e -engine tpm2tss -in ${DIR}/data.txt -out ${DIR}/enc_data -K ${KEY} -iv ${IV}
openssl enc -aes-256-cfb -d -engine tpm2tss -in ${DIR}/enc_data -out ${DIR}/dec_data -K ${KEY} -iv ${IV}
diff ${DIR}/data.txt ${DIR}/dec_data
rm ${DIR}/enc_data ${DIR}/dec_data

openssl enc -aes-256-ofb -e -engine tpm2tss -in ${DIR}/data.txt -out ${DIR}/enc_data -K ${KEY} -iv ${IV}
openssl enc -aes-256-ofb -d -engine tpm2tss -in ${DIR}/enc_data -out ${DIR}/dec_data -K ${KEY} -iv ${IV}
diff ${DIR}/data.txt ${DIR}/dec_data

# Release persistent HANDLE
tpm2_evictcontrol -a o -c ${HANDLE}

