
/*
 * CPSC 526 Assignment 4
 * Geordie Tait
 * 10013837
 * T02
 *
 * Encrypted file transfer server
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <getopt.h>
#include <time.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#define DELIM       "," // splitter for messages

// global variables nicely grouped
struct {
    int srcPort;        // listening port
    char key[32];       // secret key
    char buffer[1024];  // temporary buffer for input
    char outbuf[1024];  // buffer for output

} globals;

// print current local time as a string
void printTime() {
    time_t seconds;
    time(&seconds);
    struct tm *local;
    local = localtime(&seconds);
    printf("%02d:%02d:%02d: ", local->tm_hour, local->tm_min, local->tm_sec);
}

// report error message & exit
void die( const char * errorMessage, ...) {
    fprintf( stderr, "Error: ");
    va_list args;
    va_start( args, errorMessage);
    vfprintf( stderr, errorMessage, args);
    fprintf( stderr, "\n");
    va_end( args);
    exit(-1);
}

// read a line of text from file descriptor into provided buffer, up to provided char limit
int readLineFromFd( int fd, char * buff, int max) {
    char * ptr = buff;
    int count = 0;
    int result = 1;
    
    while (1) {

        // try to read in the next character from fd, exit loop on failure
        if (read(fd, ptr, 1) < 1) {
            result = 0;
            break;
        }

        // character stored, now advance ptr and character count
        ptr ++;
        count++;

        // if last character read was a newline, exit loop
        if (*(ptr - 1) == '\n') break;

        // if the buffer capacity is reached, exit loop
        if (count >= max - 1) break;        
    }
    
    // rewind ptr to the last read character
    ptr --;

    // trim trailing spaces (including new lines, telnet's \r's)
    while (ptr > buff && isspace(*ptr)) {
        ptr--;
    }

    // terminate the string
    * (ptr + 1) = '\0';
    
    return result;
}

// write a string to file descriptor
int writeStrToFd( int fd, char * str) {
    return write( fd, str, strlen( str));
}

// handle crypto errors
void handleErrors(void) {
    printTime();
    printf("Decryption error\n");
}

// encrypt a string using null, aes128 or aes256
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
        unsigned char *iv, unsigned char *ciphertext, int mode) {

    // null cipher
    if (mode == 0) {
        strcpy(ciphertext, plaintext);
        return plaintext_len;
    }

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (mode == 1) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
            handleErrors();
    }
    else {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// decrypt a string using null, aes128 or aes256
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
        unsigned char *iv, unsigned char *plaintext, int mode) {

    // null cipher
    if (mode == 0) {
        strcpy(plaintext, ciphertext);
        return ciphertext_len;
    }

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (mode == 1) {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
            handleErrors();
    }
    else {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// generate a string of random alphanumeric characters
void getRandomStr(char *out, size_t n) {
    char chars[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    srand(time(NULL));
    while (n-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof(chars) - 1);
        *out++ = chars[index];
    }
    *out = 0;
}

// handle the connection
void processConn(int connSockFd, char *result) {

    unsigned char ciphertext[sizeof(globals.buffer)*2];
    unsigned char decryptedtext[sizeof(globals.buffer)*2];
    int decryptedtext_len, ciphertext_len;

    // get and print connecting IP
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    int res = getpeername(connSockFd, (struct sockaddr *)&addr, &addr_size);
    char clientip[20];
    strcpy(clientip, inet_ntoa(addr.sin_addr));
    printTime();
    printf("New connection from %s", clientip);

    // receive cipher and nonce from client
    if (readLineFromFd(connSockFd, globals.buffer, sizeof(globals.buffer)) < 1) {
        strcpy(result, "error: connection failed during initial handshake");
        return;
    }
    
    // parse cipher and nonce
    char *cipher;
    cipher = strtok(globals.buffer, DELIM);
    char *nonce;
    nonce = strtok(NULL, DELIM);
    if (nonce == NULL || strtok(NULL, DELIM) != NULL) {
        strcpy(result, "error: invalid cipher or nonce");
        return;
    }

    // check if cipher is valid
    if (strcmp(cipher, "null") != 0
            && strcmp(cipher, "aes128") != 0
            && strcmp(cipher, "aes256") != 0) {
        writeStrToFd(connSockFd, "Error: invalid cipher");
        strcpy(result, "error: invalid cipher");
        printf("\n");
        return;
    }
    int ciph;
    if (strcmp(cipher, "aes128") == 0)
        ciph = 1;
    else if (strcmp(cipher, "aes256") == 0)
        ciph = 2;
    else
        ciph = 0;
    
    // print cipher and nonce
    printf(" cipher=%s\n", cipher);
    printTime();
    printf("nonce=%s\n", nonce);

    // calculate and print iv
    char plain[128], iv[65], hashiv[SHA256_DIGEST_LENGTH];
    sprintf(plain, "%s%64sIV", globals.key, nonce);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);    
    SHA256_Update(&sha256, plain, strlen(plain));
    SHA256_Final(hashiv, &sha256);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(iv + (i*2), "%02x", hashiv[i]);
    iv[64] = 0;
    printTime();
    printf("IV=%s\n", iv);

    // calculate and print sk
    char sk[65], hashsk[SHA256_DIGEST_LENGTH];
    sprintf(plain, "%s%64sSK", globals.key, nonce);
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plain, strlen(plain));
    SHA256_Final(hashsk, &sha256);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(sk + (i*2), "%02x", hashsk[i]);
    sk[64] = 0;
    printTime();
    printf("SK=%s\n", sk);
    
    // begin encrypting all traffic with specified cipher

    // send random challenge to client, encrypted with secret key
    char challenge[16];
    getRandomStr(challenge, sizeof(challenge));
    ciphertext_len = encrypt(challenge, strlen ((char *)challenge), globals.key, iv, ciphertext, 1);
    ciphertext_len = encrypt(ciphertext, ciphertext_len, sk, iv, ciphertext, ciph);
    if (write(connSockFd, ciphertext, ciphertext_len) < 1) {
        strcpy(result, "error: connection failed during auth");
        return;
    }
    
    // receive computed response from client
    int n = read(connSockFd, globals.buffer, sizeof(globals.buffer));
    if (n < 1) {
        strcpy(result, "error: connection failed during auth");
        return;
    }
    decryptedtext_len = decrypt(globals.buffer, n, sk, iv, decryptedtext, ciph);
    decryptedtext[decryptedtext_len] = 0;
    
    // check and report success/failure of authentication
    if (strcmp(challenge, decryptedtext) != 0) {
        strcpy(plain, "Error: authentication failed");
        ciphertext_len = encrypt(plain, strlen((char *)plain), sk, iv, ciphertext, ciph);
        write(connSockFd, ciphertext, ciphertext_len);
        strcpy(result, "error: connection failed during auth");
        return;
    }
    strcpy(plain, "AUTHOK");
    ciphertext_len = encrypt(plain, strlen ((char *)plain), sk, iv, ciphertext, ciph);
    if (write(connSockFd, ciphertext, ciphertext_len) < 1) {
        strcpy(result, "error: connection failed during auth");
        return;
    }
    
    // receive operation and filename from client
    n = read(connSockFd, globals.buffer, sizeof(globals.buffer));
    if (n < 1) {
        strcpy(result, "error: connection failed during op specification");
        return;
    }
    decryptedtext_len = decrypt(globals.buffer, n, sk, iv, decryptedtext, ciph);
    decryptedtext[decryptedtext_len] = 0;
   
    // parse op and file
    char *op;
    op = strtok(decryptedtext, DELIM);
    char *filename;
    filename = strtok(NULL, DELIM);
    if (filename == NULL || strtok(NULL, DELIM) != NULL) {
        strcpy(result, "error: invalid file or operation");
        return;
    }
    printTime();
    printf("command:%s, filename:%s\n", op, filename);

    // check if op is valid
    if (strcmp(op, "read") != 0
            && strcmp(op, "write") != 0) {
        strcpy(plain, "Error: invalid operation");
        ciphertext_len = encrypt(plain, strlen ((char *)plain), sk, iv, ciphertext, ciph);
        write(connSockFd, ciphertext, ciphertext_len);
        strcpy(result, "error: invalid operation");
        return;
    }

    // check if file is valid and open it
    FILE *fp;
    int r = 0;
    if (strcmp(op, "write") == 0) {
        fp = fopen(filename, "w+");
    }
    else {
        fp = fopen(filename, "r+");
        r = 1;
    }
    if (fp == NULL) {
        strcpy(plain, "Error: invalid file");
        ciphertext_len = encrypt(plain, strlen ((char *)plain), sk, iv, ciphertext, ciph);
        write(connSockFd, ciphertext, ciphertext_len);
        strcpy(result, "error: invalid file");
        return;
    }    
   
    // report operation can proceed
    strcpy(plain, "PROCEED");
    ciphertext_len = encrypt(plain, strlen ((char *)plain), sk, iv, ciphertext, ciph);
    if (write(connSockFd, ciphertext, ciphertext_len) < 1) {
        strcpy(result, "error: connection failed during op specification");
        return;
    }
    
    // initialize variables for select()
    fd_set fds;
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    int ret;

    // send or receive data chunks
    while (1) {
        bzero(globals.buffer, sizeof(globals.buffer));
        bzero(ciphertext, sizeof(ciphertext));
        bzero(decryptedtext, sizeof(decryptedtext));
        
        // reading
        if (r) {
            int n = fread(globals.buffer, sizeof(globals.buffer[0]),
                    sizeof(globals.buffer)/2*sizeof(globals.buffer[0]), fp);
            if (n < 0) {
                strcpy(result, "error: could not read from file");
                return;
            }
            if (n < 1) break;
            ciphertext_len = encrypt(globals.buffer, n, sk, iv, ciphertext, ciph);
            if (write(connSockFd, ciphertext, ciphertext_len) < 1) {
                strcpy(result, "error: connection failed during reading");
                return;
            }
        }

        // writing
        else {
            int n = read(connSockFd, globals.buffer, 528);//sizeof(globals.buffer));
            if (n < 0) {
                strcpy(result, "error: connection failed during writing");
                return;
            }
            if (n < 1) break;
            decryptedtext_len = decrypt(globals.buffer, n, sk, iv, decryptedtext, ciph);
            decryptedtext[decryptedtext_len] = 0;
            int m = fwrite(decryptedtext, sizeof(decryptedtext[0]),
                    decryptedtext_len / sizeof(decryptedtext[0]), fp);
            if (m < 1) {
                strcpy(result, "error: could not write to file");
                return;
            }
        }
    }

    // complete
    fclose(fp);
    strcpy(result, "success");
}

// main program function (entry point)
int main( int argc, char ** argv) {
    printf("Encrypted file transfer server 1.0\n");

    // parse command line arguments
    if (argc != 3) die( "Usage: ./server port key\n");
    char *end = NULL;
    globals.srcPort = strtol(argv[1], &end, 10);
    if (*end != 0) die("Bad listening port %s", argv[1]);
    strcpy(globals.key, argv[2]);

    // create a listening socket on the given source port
    struct sockaddr_in servaddr;
    int listenSockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSockFd < 0) die("Socket() failed");
    bzero((char*) &servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htons(INADDR_ANY);
    servaddr.sin_port = htons(globals.srcPort);
    if (bind(listenSockFd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0)
        die("Could not bind listening socket: %s", strerror(errno));

    // listen for a new connection
    if (listen(listenSockFd, 3) != 0)
        die( "Could not listen for incoming connections");

    printf("Listening on port %d\n", globals.srcPort);
    printf("Using secret key \"%s\"\n", globals.key);

    // main server loop
    while (1) {

        // accept a new connection
        struct sockaddr_in clientaddr;
        socklen_t clientaddr_size = sizeof(clientaddr);
        int connSockFd = accept(listenSockFd, (struct sockaddr*)&clientaddr, &clientaddr_size);
        if (connSockFd < 0) {
            printTime();
            printf("Accept() failed: %s\n", strerror(errno));
            continue;
        }

        // initialise the crypto library
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OPENSSL_config(NULL);

        // handle the connection
        char result[128];
        processConn(connSockFd, result);
        printTime();
        printf("status: %s\n", result);

        // clean up and close socket
        EVP_cleanup();
        ERR_free_strings();
        close(connSockFd);
    }

    // end of program
    close(listenSockFd);
    return 0;
}


