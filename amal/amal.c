/** 
 * PA1 by Conor McFadden and Patrick Dodds
 *  
 * File: ____
 * Date: ____
 * 
 * This code abides by the JMU Honor Code
*/

#include "../myCrypto.h"
#include <fcntl.h>
#include <sys/stat.h>

void main(int argc, char *argv[]) {

    uint8_t key[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH];
    unsigned key_len = EVP_MAX_KEY_LENGTH;
    unsigned iv_len = EVP_MAX_IV_LENGTH;
    int fd_key, fd_iv, fd_bunny, fd_control, fd_data;
    // Create new blank file
    FILE *log = fopen("amal/logAmal.txt", "w");
    if (!log)
    {
        fprintf(stderr, "Amal: couldn't create log file\n");
        fclose(log);
        exit(-1);
    }

    // Open control fd
    fd_control = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC);
    if (fd_control == -1)
    {
        fprintf(stderr, "Amal: couldn't open control fd\n");
        fclose(log);
        exit(-1);
    }

    // // Open data fd
    // fprintf(stdout, "\n%s\n", argv[2]);
    fd_data = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC);
    if (fd_data == -1)
    {
        fprintf(stderr, "Amal: couldn't open data fd\n");
        fclose(log);
        exit(-1);
    }

    // Opens the key fd
    fd_key = open("key.bin", O_RDONLY);
    if (fd_key == -1)
    {
        fprintf(stderr, "\nAmal: Couln't open key.bin\n");
        fclose(log);
        exit(-1);
    }

    // Dumping the bytes of key in hex
    read (fd_key, key, key_len);
    fprintf(log, "\nUsing this symmetric key of length %d bytes\n", key_len);
    BIO_dump_fp (log, (const char *) key, key_len);
    close( fd_key);

    // Opens the iv fd
    fd_iv = open("iv.bin", O_RDONLY);
    if(fd_iv == -1) {
        fprintf(stderr, "\nAmal: Couldnt open iv.bin\n");
        fclose(log);
        exit(-1);   
    }

    // Drumping the bytes of iv in hex
    read(fd_iv, iv, iv_len);
    fprintf(log, "\nUsing this iv of length %d bytes\n", iv_len);
    BIO_dump_fp(log, (const char *) iv, iv_len);
    close(fd_iv);

    fd_bunny = open("bunny",  O_WRONLY | O_CREAT | O_RDONLY);
    if(fd_bunny == -1) {
        fprintf(stderr, "\nAmal: Couldnt open bunny\n");
        fclose(log);
        exit(-1);   
    }

    // Encrypt the file
    int bunny_cipher_len = encryptFile( fd_bunny, fd_data, (const uint8_t *) &fd_key, (const uint8_t *) &fd_iv );

    // write to data channel with the num of bytes 
    // uint8_t bunny_ciphertext[bunny_cipher_len];
    // int bunny_bytes = write(fd_bunny, (const char *) bunny_ciphertext, bunny_cipher_len);
    // if (bunny_bytes == -1) {
    //     fprintf(stderr, "\nAmal: Couldnt write to bunny\n");
    //     fclose(log);
    //     close(fd_bunny);
    //     exit(-1);
    // }
    // close( fd_key);
    // close(fd_iv);
    close(fd_data);
    close(fd_control);
    close(fd_bunny);
}