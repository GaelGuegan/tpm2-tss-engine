#!/bin/bash

set -eufx

export OPENSSL_ENGINES=${PWD}/.libs
export LD_LIBRARY_PATH=$OPENSSL_ENGINES:${LD_LIBRARY_PATH-}
export PATH=${PWD}:${PATH}

DIR=$(mktemp -d)
echo -n "hello world goodbye world bonjour le monde aurevoir" > ${DIR}/data.txt

# Create an Primary key pair
echo "Generating primary key"
PARENT_CTX=${DIR}/primary_owner_key.ctx

tpm2_startup -T mssim -c || true

tpm2_createprimary -a o -g sha256 -G rsa -o ${PARENT_CTX}
tpm2_flushcontext -t

# Create an Sym key
echo "Generating SYM key"
TPM_RSA_PUBKEY=${DIR}/rsakey.pub
TPM_RSA_KEY=${DIR}/rsakey
ALGO="aes"
tpm2_create -C ${PARENT_CTX} -g sha256 -G ${ALGO} -u ${TPM_RSA_PUBKEY} -r ${TPM_RSA_KEY} -A sign\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth
tpm2_flushcontext -t

# Load Key to persistent handle
RSA_CTX=${DIR}/rsakey.ctx
tpm2_load -C ${PARENT_CTX} -u ${TPM_RSA_PUBKEY} -r ${TPM_RSA_KEY} -o ${RSA_CTX}
tpm2_flushcontext -t

HANDLE=$(tpm2_evictcontrol -a o -c ${RSA_CTX} | cut -d ' ' -f 2)
tpm2_flushcontext -t

KEY=$(echo ${HANDLE} | cut -d 'x' -f 2)
IV="0123456789012345"
echo -n $IV > ${DIR}/iv

# Encrypt Data
tpm2_encryptdecrypt -c ${HANDLE} -I ${DIR}/data.txt -o ${DIR}/enc_data -i ${DIR}/iv
openssl enc -aes-256-cfb -e -engine tpm2tss -in ${DIR}/data.txt -out ${DIR}/enc_data1 -K ${KEY} -iv ${IV}
openssl enc -aes-256 -e -engine tpm2tss -in ${DIR}/data.txt -out ${DIR}/enc_data2 -K ${KEY} -iv ${IV}

# Decrypt Data
tpm2_encryptdecrypt -c ${HANDLE} -I ${DIR}/enc_data -o ${DIR}/dec_data -D -i ${DIR}/iv
openssl enc -aes-256-cfb -d -engine tpm2tss -in ${DIR}/enc_data1 -out ${DIR}/dec_data1 -K ${KEY} -iv ${IV}
openssl enc -aes-256 -d -engine tpm2tss -in ${DIR}/enc_data2 -out ${DIR}/dec_data2 -K ${KEY} -iv ${IV}

set +e

diff ${DIR}/data.txt ${DIR}/dec_data
diff ${DIR}/data.txt ${DIR}/dec_data1
diff ${DIR}/data.txt ${DIR}/dec_data2

cat ${DIR}/dec_data1
cat ${DIR}/dec_data2

# Release persistent HANDLE
tpm2_evictcontrol -a o -c ${HANDLE}

# Test Gen Key
tpm2tss-genkey -a aes -s 128 ${DIR}/mykey
