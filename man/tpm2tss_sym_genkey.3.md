% tpm2tss-tpm2data_write(1) tpm2-tss-engine | Library calls
%
% FEBRUARY 2019

# NAME
**tpm2tss_sym_genkey** -- Make an EVP_CIPHER_CTX object

# SYNOPSIS

**#include <tpm2tss.h>**

**int
tpm2tss_sym_genkey(EVP_CIPHER_CTX *cipher, TPMI_ALG_PUBLIC algo, TPMI_ALG_SYM_MODE mode, int bits, char *password, TPM2_HANDLE parentHandle);**

# DESCRIPTION

**tpm2tss_sym_genkey** issues the generation of an EVP_CIPHER_CTX `cipher` using the TPM.
The symmetric algorithm is determined by `algo`.
In theory, TPM allow 3 differents types of symmetric algorithm : `AES, CAMELLIA and SM4`.
The cipher block mode of operation is determined by `mode`.
The key length is determined by `bits`.
The new key will be protected by `password`.

# RETURN VALUE

Upon successful completion **tpm2tss_sym_genkey**() returns 1. Otherwise 0.

## AUTHOR

Written by Gael Guegan.

## COPYRIGHT

Copyright (C) 2019 Schneider-Electric. License BSD 3-clause.”

## SEE ALSO

openssl(1), tpm2tss_genkey(1)
