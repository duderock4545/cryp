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

    // Constants and file descriptors
    uint8_t key[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH];
    unsigned key_len = SYMMETRIC_KEY_LEN;
    unsigned iv_len = INITVECTOR_LEN;
    int fd_key, fd_iv, fd_bunny, fd_control, fd_data;

    // Create log file
    FILE *log = fopen("basim/logBasim.txt", "w");
    if (!log)
    {
        fprintf(log, "Basim: couldn't create log file\n");
        exit(-1);
    }

    // Open control and data fd
    fd_control = atoi( argv[1] );
    fd_data = atoi( argv[2] );

        // Opens the key fd
    fd_key = open("key.bin", O_RDONLY);
    if (fd_key == -1)
    {
        fprintf(log, "\nBasim: Couln't open key.bin\n");
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
        fprintf(log, "\nBasim: Couldnt open iv.bin\n");
        fclose(log);
        exit(-1);   
    }

    // Dumping the bytes of iv in hex
    read(fd_iv, iv, iv_len);
    fprintf(log, "\nUsing this iv of length %d bytes\n", iv_len);
    BIO_dump_fp(log, (const char *) iv, iv_len);
    close(fd_iv);

    // Create bunny.decr file
    FILE *bunny = fopen("bunny.decr", "w");
    if (!bunny)
    {
        fprintf(log, "Basim: couldn't create bunny file\n");
        exit(-1);
    }

    // Opens the bunny.decr fd
    fd_bunny = open("bunny.decr", O_WRONLY);
    if(fd_bunny == -1) {
        fprintf(log, "\nBasim: Couldnt open bunny fd\n");
        fclose(log);
        exit(-1);   
    }

    // Decrypts from fd_data
    int decrypt_status = decryptFile(fd_data, fd_bunny, key, iv);

    // Cleans up code
    close(fd_bunny);
    close(fd_data);
    close(fd_control);
}