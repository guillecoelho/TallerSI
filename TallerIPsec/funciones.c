/* 
 * File:   funciones.c
 * Author: Grupo 03
 *
 * Created on 12 de julio de 2010, 18:52
 */

#include <gcrypt.h>

void error(const char *what, gcry_error_t err) {
    fprintf(stderr, "%s failed: %s\n", what, gcry_strerror(err));
    exit(1);
}

void decrypt (unsigned char* EncData, int datalen, const char* encAlg, const char* encKey) {
    gcry_cipher_hd_t gcryCipherHd;
    gcry_error_t err;
    size_t nonceLenght;
    size_t encKeyLenght;
    unsigned int index;

    // Get the size of IV for the selected algorithm
    nonceLenght = gcry_cipher_get_algo_blklen(GCRY_CIPHER_3DES); 
    if (nonceLenght == 0) { printf("gcry_cipher_get_algo_blklen failed"); exit(1);}

    // Get IV from the header of the data
    unsigned char* nonce = malloc(nonceLenght);
    for (index=0; index<nonceLenght; index++) {
        nonce[index] = EncData[index];
    }

    // Shift data to the left <nonceLenght> positions
    for (index=0; index<datalen; index++) {
        EncData[index] = EncData[index+nonceLenght];
    }

    encKeyLenght = strlen(encKey);
    // Preperate the chiper handler
    prepare(&gcryCipherHd, GCRY_CIPHER_3DES, encKey, encKeyLenght, nonce, nonceLenght);

    err = gcry_cipher_decrypt(
        gcryCipherHd,
        EncData,
        datalen - nonceLenght,
        EncData,
        datalen - nonceLenght);
    if (err) { error("gcry_cipher_decrypt", err); }

    gcry_cipher_close(gcryCipherHd);
}

void encrypt (unsigned char* EncData, unsigned char* data, int datalen, const char* encAlg, const char* encKey) {
    gcry_cipher_hd_t gcryCipherHd;
    gcry_error_t err;
    size_t nonceLenght;
    size_t encKeyLenght;
    unsigned int index;

    // Get the size of IV for the selected algorithm
    nonceLenght = gcry_cipher_get_algo_blklen(GCRY_CIPHER_3DES); 
    if (nonceLenght == 0) { printf("gcry_cipher_get_algo_blklen failed"); exit(1);}

    // Generate random nonce to use as IV
    unsigned char* nonce = malloc(nonceLenght);
    gcry_create_nonce(nonce, nonceLenght);

    encKeyLenght = strlen(encKey);
    // Preperate the chiper handler
    prepare(&gcryCipherHd, GCRY_CIPHER_3DES, encKey, encKeyLenght, nonce, nonceLenght);

    // Encryt the data
    err = gcry_cipher_encrypt(
        gcryCipherHd, 
        EncData,   
        datalen,   
        data,    
        datalen); 
    if (err) { error("gcry_cipher_encrypt", err); }

    // Shift data to the right <nonceLenght> positions
    for (index=datalen+nonceLenght-1; index>nonceLenght-1; index--) {
        EncData[index] = EncData[index-nonceLenght];
    }

    // Add IV to the encripted data
    for (index=0; index<nonceLenght; index++) {
        EncData[index] = nonce[index];
    }

    gcry_cipher_close(gcryCipherHd);
}

void prepare(gcry_cipher_hd_t *hd, const char* encAlg, const char* encKey, size_t encKeyLenght, const char* nonce, size_t nonceLenght) {
    gcry_error_t err;

    err = gcry_cipher_open (hd, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0);
    if (err) { error("gcry_cipher_open", err); }

    err = gcry_cipher_setkey (*hd, encKey, encKeyLenght);
    if (err) { error("gcry_cipher_setkey", err); }

    err = gcry_cipher_setiv(*hd, nonce, nonceLenght);
    if (err) { error("gcry_cipher_setiv", err); }
}