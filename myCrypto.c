/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By: 
     1- 
     
Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}


//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

// For the following Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText )
{
    int status;
    unsigned len = 0, encryptedLen = 0;

    // init encrypt operation
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) 
        handleErrors("encrypt: failed to create CTX");
    
    
    status = EVP_EncryptInit_ex (ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptInit_ex");
    
    // Perform the encryption
    status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptUpdate");
    encryptedLen += len;

    // Advance ciphertext pointer
    pCipherText += len;

    // Finalize encryption
    status = EVP_EncryptFinal_ex(ctx, pCipherText, &len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return encryptedLen;
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
    int status;
    unsigned len = 0, decryptedLen = 0;

    // init encrypt operation
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) 
        handleErrors("decrypt: failed to create CTX");
    
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptInit_ex");
    
    // Perform the encryption
    status = EVP_DecryptUpdate(ctx, pDecryptedText, &len, pCipherText, cipherText_len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptUpdate");
    decryptedLen += len;

    // Advance ciphertext pointer
    pDecryptedText += len;

    // Finalize encryption
    status = EVP_DecryptFinal_ex(ctx, pDecryptedText, &len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return decryptedLen;

}


//-----------------------------------------------------------------------------


static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application

//-----------------------------------------------------------------------------

// Encrypts fd_in, writes ciphertext to fd_out, and return total ciphertext bytes
int encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    // Num of bytes read per loop, total bytes of cipher
    unsigned plaintext_len, encrypted_len, update_len = 0;

    // Error status buffer
    int status;

    // Create the context for the decryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) 
        handleErrors("EncryptFile: failed to create CTX");

    // Initialize the encryption
    status = EVP_EncryptInit_ex (ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("EncryptFile: failed to EncryptInit_ex");
        
    // Loops by reading a chunk of plaintext, encrypting it, then writing to fd_out
    while ( ( plaintext_len = read(fd_in, plaintext, PLAINTEXT_LEN_MAX) ) > 0 )
    {
        // Encrypt the chunk of bytes read from fd_in
        status = EVP_EncryptUpdate(ctx, ciphertext, &update_len, plaintext, plaintext_len);
        if (status != 1)
            handleErrors("encrypt: failed to EncryptUpdate");

        // Update total encryption length
        encrypted_len += update_len;

        // Writes ciphertext to fd_out
        write(fd_out, ciphertext, update_len);
    }

    // Plaintext error check
    if (plaintext_len == -1)
        handleErrors("encrypt: failed to read plaintext");
    
    // Finalize encryption
    status = EVP_EncryptFinal_ex(ctx, ciphertext, &update_len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");

    // Write the final encrypt
    write(fd_out, ciphertext, update_len);

    // Free context
    EVP_CIPHER_CTX_free(ctx);

    return encrypted_len + update_len;
}

//-----------------------------------------------------------------------------

// Decrypts fd_in, writes decryptext to fd_out, and return total decryptext bytes
int decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    // Num of bytes read per loop, total bytes of decryption
    unsigned ciphertext_len, decrypted_len, update_len = 0;

    // Error status buffer
    int status;

    // Create the context for the decryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) 
        handleErrors("DecryptFile: failed to create CTX");

    // Initialize the decryption
    status = EVP_DecryptInit_ex (ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("DecryptFile: failed to EncryptInit_ex");
    
    // Loops by reading a chunk of ciphertext, decrypting it, then writing to fd_out
    while ( ( ciphertext_len = read(fd_in, ciphertext, CIPHER_LEN_MAX) ) > 0 )
    {
        // Decrypt the chunk of bytes read from fd_in
        status = EVP_DecryptUpdate(ctx, decryptext, &update_len, ciphertext, ciphertext_len);
        if (status != 1)
            handleErrors("DecryptFile: failed to DecryptUpdate");

        // Update total decryption length
        decrypted_len += update_len;

        // Writes cecryptext to fd_out
        write(fd_out, decryptext, update_len);
    }

    // Ciphertext error check
    if (ciphertext_len == -1)
        handleErrors("DecryptFile: failed to read ciphertext");
    
    // Finalize decryption
    status = EVP_DecryptFinal_ex(ctx, decryptext, &update_len);
    if (status != 1)
        handleErrors("DecryptFile: failed to DecryptFinal_ex");

    // Write the final decrypt
    write(fd_out, decryptext, update_len);

    // Free context
    EVP_CIPHER_CTX_free(ctx);

    return decrypted_len + update_len;
}
