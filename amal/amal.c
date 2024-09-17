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
    unsigned key_len = SYMMETRIC_KEY_LEN;
    unsigned iv_len = INITVECTOR_LEN;
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
    fd_control = atoi( argv[1] );
    fd_data = atoi( argv[2] );
 
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

    // Opens the bunny file descriptor
    fd_bunny = open("bunny.mp4", O_RDONLY);
    if(fd_bunny == -1) {
        fprintf( log , "\nAmal: Couldnt open bunny\n");
        fclose(log);
        exit(-1);   
    }

    // Encrypt the file
    int bunny_cipher_len = encryptFile( fd_bunny, fd_data, key, iv);

    // Clean ups
    close(fd_data);
    close(fd_control);
    close(fd_bunny);
}