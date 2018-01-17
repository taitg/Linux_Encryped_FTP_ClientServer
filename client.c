
/*
 * CPSC 526 Assignment 4
 * Geordie Tait
 * 10013837
 * T02
 *
 * Encrypted file transfer client
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

#define DELIM   "," // splitter for messages

// global variables nicely grouped
struct {
    int srcPort;        // listening port
    char key[32];       // secret key
    char buffer[1024];  // temporary buffer for input
    char outbuf[2048];  // buffer for output
} globals;

// report error message & exit
void die( const char * errorMessage, ...) {
    fprintf( stderr, "Error: ");
    va_list args;
    va_start( args, errorMessage);
    vfprintf( stderr, errorMessage, args);
    fprintf( stderr, "\n");
    va_end( args);
    EVP_cleanup();
    ERR_free_strings();
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
        die("Could not initialize cipher context");

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (mode == 1) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
            die("Could not initialize AES128");
    }
    else {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            die("Could not initialize AES256");
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        die("Encryption failed");
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        die("Encryption failed");
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
        die("Could not initialize cipher context");

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (mode == 1) {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
            die("Could not initialize AES128");
    }
    else {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            die("Could not initialize AES256");
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        die("Decryption failed");
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        die("Wrong key");
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

// handle connection to server
void processConn(char *cmd, char *fn, char *host, int port, char *cipher) {

    unsigned char ciphertext[sizeof(globals.buffer)*2];
    unsigned char decryptedtext[sizeof(globals.buffer)*2];
    int decryptedtext_len, ciphertext_len;
    int destSockFd;
    struct sockaddr_in destaddr;
    struct hostent *server;

    // open destination socket
    destSockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (destSockFd < 0)
        die("Destination socket failed");

    // get destination host
    server = gethostbyname(host);
    if (server == NULL)
        die("Destination server null");

    // connect to destination server
    bzero((char *)&destaddr, sizeof(destaddr));
    destaddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&destaddr.sin_addr.s_addr, server->h_length);
    destaddr.sin_port = htons(port);
    if (connect(destSockFd, (struct sockaddr *)&destaddr, sizeof(destaddr)) < 0)
        die("Connection to server failed");

    // send cipher and nonce to server
    char nonce[16];
    getRandomStr(nonce, sizeof(nonce));
    sprintf(globals.buffer, "%s%s%s\n", cipher, DELIM, nonce);
    if (writeStrToFd(destSockFd, globals.buffer) < 1)
        die("Connection failed during initial handshake");

    int ciph;
    if (strcmp(cipher, "aes128") == 0)
        ciph = 1;
    else if (strcmp(cipher, "aes256") == 0)
        ciph = 2;
    else
        ciph = 0;

    // calculate iv
    char plain[128], iv[65], hashiv[SHA256_DIGEST_LENGTH];
    sprintf(plain, "%s%64sIV", globals.key, nonce);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plain, strlen(plain));
    SHA256_Final(hashiv, &sha256);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(iv + (i*2), "%02x", hashiv[i]);
    }
    iv[64] = 0;

    // calculate sk
    char sk[65], hashsk[SHA256_DIGEST_LENGTH];
    sprintf(plain, "%s%64sSK", globals.key, nonce);
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plain, strlen(plain));
    SHA256_Final(hashsk, &sha256);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(sk + (i*2), "%02x", hashsk[i]);
    }
    sk[64] = 0;

    // begin encrypting all traffic with specified cipher

    // receive random challenge
    bzero(globals.buffer, sizeof(globals.buffer));
    int n = read(destSockFd, globals.buffer, sizeof(globals.buffer));
    if (n < 1) die("Connection failed during auth");
    decryptedtext_len = decrypt(globals.buffer, n, sk, iv, decryptedtext, ciph);
    decryptedtext[decryptedtext_len] = 0;
    decryptedtext_len = decrypt(decryptedtext, decryptedtext_len, globals.key, iv, decryptedtext, 1);
    decryptedtext[decryptedtext_len] = 0;

    // compute and send response using secret key
    bzero(globals.buffer, sizeof(globals.buffer));
    bzero(plain, sizeof(plain));
    sprintf(plain, "%s", decryptedtext);
    ciphertext_len = encrypt(plain, strlen ((char *)plain), sk, iv, ciphertext, ciph);
    if (write(destSockFd, ciphertext, ciphertext_len) < 1)
        die("Connection failed during auth");

    // receive success/failure of authentication
    bzero(globals.buffer, sizeof(globals.buffer));
    n = read(destSockFd, globals.buffer, sizeof(globals.buffer));
    if (n < 1) die("Connection failed during auth");
    decryptedtext_len = decrypt(globals.buffer, n, sk, iv, decryptedtext, ciph);
    decryptedtext[decryptedtext_len] = 0;
    if (strcmp(decryptedtext, "AUTHOK") != 0)
        die("Authorization failed");

    // send operation and filename to server
    bzero(globals.buffer, sizeof(globals.buffer));
    sprintf(plain, "%s%s%s", cmd, DELIM, fn);
    ciphertext_len = encrypt(plain, strlen((char *)plain), sk, iv, ciphertext, ciph);
    if (write(destSockFd, ciphertext, ciphertext_len) < 1) 
        die("Connection failed while transmitting operation");
    int r = 0;
    if (strcmp(cmd, "read") == 0)
        r = 1;   

    // receive whether op can proceed
    bzero(globals.buffer, sizeof(globals.buffer));
    n = read(destSockFd, globals.buffer, sizeof(globals.buffer));
    if (n < 1) die("Connection failed before transmitting data");
    decryptedtext_len = decrypt(globals.buffer, n, sk, iv, decryptedtext, ciph);
    decryptedtext[decryptedtext_len] = 0;
    if (strcmp(decryptedtext, "PROCEED") != 0) {
        if (r) die("File could not be read");
        else die("File could not be written to");
    }

    // send/receive data chunks
    while (1) {
        bzero(globals.buffer, sizeof(globals.buffer));
        bzero(decryptedtext, sizeof(decryptedtext));
        bzero(ciphertext, sizeof(ciphertext));

        // reading
        if (r) {
            int n = read(destSockFd, globals.buffer, 528);//sizeof(globals.buffer));
            if (n < 0) die("Connection failed during data transfer");
            if (n < 1) break;
            decryptedtext_len = decrypt(globals.buffer, n, sk, iv, decryptedtext, ciph);
            decryptedtext[decryptedtext_len] = 0;
            fwrite(decryptedtext, 1, decryptedtext_len, stdout);
        }

        // writing
        else {
            int n = read(STDIN_FILENO, globals.buffer, sizeof(globals.buffer)/2);
            if (n < 0) die("Could not read from standard input");
            if (n < 1) break;
            ciphertext_len = encrypt(globals.buffer, n, sk, iv, ciphertext, ciph);
            if (write(destSockFd, ciphertext, ciphertext_len) < 0)
                die("Connection failed during data transfer");
        }
    }
    
    // success
    fprintf(stderr, "OK\n");
    close(destSockFd);
}

// print usage
void usage() {
    die( "Usage: ./client command filename hostname:port cipher key\n");
}

// main program function (entry point)
int main( int argc, char ** argv) {
    char *hostname, *portstr;
    char command[8], filename[256], hostport[128], cipher[8];
    int port;

    // parse command line arguments
    if (argc != 6) usage();
    strcpy(command, argv[1]);
    strcpy(filename, argv[2]);
    strcpy(hostport, argv[3]);
    strcpy(cipher, argv[4]);
    bzero(globals.key, sizeof(globals.key));
    strcpy(globals.key, argv[5]);

    hostname = strtok(hostport, ":");
    portstr = strtok(NULL, ":");
    if (portstr == NULL || strtok(NULL, ":") != NULL) usage();
    char *end = NULL;
    port = strtol(portstr, &end, 10);

    // check for invalid arguments
    if (*end != 0)
        die("Invalid port: %s", portstr);
    if (strcmp(command, "read") != 0 
            && strcmp(command, "write") != 0)
        die("Invalid command: %s", command);
    if (strcmp(cipher, "null") != 0 
            && strcmp(cipher, "aes128") != 0 
            && strcmp(cipher, "aes256") != 0)
        die("Invalid cipher: %s", cipher);

    // Initialise the crypto library
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    // handle the connection
    processConn(command, filename, hostname, port, cipher);

    // clean up and exit
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}


