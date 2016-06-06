/**
 * rsacrypt.c
 *  RSA Encrypt/Decrypt & Sign/Verify Test Program for OpenSSL
 *  wrtten by blanclux
 *  This software is distributed on an "AS IS" basis WITHOUT WARRANTY OF ANY KIND.
 * 
 * modified for use in clockwork on 6/5/16
 *  
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void printHex(const char *title, const unsigned char *s, int len) {
    int n = 0;
    
    printf("%s [%03d size]:", title, len);
    
    for (n = 0; n < len; ++n) {
        if ((n % 16) == 0) {
            printf("\n%04x", n);
        }
        
        printf(" %02x", s[n]);
    }
    
    printf("\n");
}


int SignCreate(RSA *privkey, char *data, int dataLen, char *signature, int *signature_len) {
    unsigned int signLen = 0;
    int ret = 0;
    char *buf = NULL;
    
    char *hash =(char *) malloc(SHA512_DIGEST_LENGTH);
    
    if (hash != NULL) {
        SHA512((const unsigned char *)data, dataLen, (unsigned char *)hash);

        ret = RSA_sign(NID_sha512, (const unsigned char *)hash, SHA512_DIGEST_LENGTH, (unsigned char *)signature, &signLen, privkey);

        if (ret == 1) {  
            printHex("SIGNATURE", (const unsigned char *)signature, signLen); 
            *signature_len = signLen;
            ret = 1;
        }

        free(hash);
    }
    
    return ret;
}


int SignCheck(RSA *pubkey,  char *data, int dataLen, char *signature, int signature_len) {
    int ret = 0;
    
    char *hash = (char *)malloc(SHA512_DIGEST_LENGTH);
    
    if (hash != NULL) {
        SHA512((const unsigned char *)data, dataLen,(unsigned char *) hash);
        
        ret = RSA_verify(NID_sha512,(const unsigned char *) hash, SHA512_DIGEST_LENGTH, (unsigned char *) signature, signature_len, pubkey);
        
        free(hash);
            
    }
    
    return ret;
}

RSA *LoadPrivate(char *file) {
    RSA *prikey = NULL;
    FILE *fd = NULL;
    
    if ((fd = fopen(file, "r")) == NULL) return NULL;
    
    prikey = PEM_read_RSAPrivateKey(fd, NULL, NULL, NULL);

    if (prikey == NULL) {
        ERR_print_errors_fp(stderr);
    }
    
    fclose(fd);
    
    return prikey;
}

RSA *LoadPublic(char *file) {
    RSA *pubkey = NULL;
    FILE *fd = NULL;
    int ret = 0;
    
    if ((fd = fopen(file, "r")) == NULL) return NULL;
    
    pubkey = PEM_read_RSAPublicKey(fd, NULL, NULL, NULL);
    
    if (pubkey == NULL) {
        ERR_print_errors_fp(stderr);
    }
    
    fclose(fd);
    
    return pubkey;
}

char *FileContents(char *filename, int *ret_size) {
    char *ret = NULL;
    FILE *fd = NULL;
    char *buf = NULL;
    struct stat stv;
    int r = 0;
    
    if ((fd = fopen(filename, "rb")) == NULL) {
        return NULL;
    }
    
    fstat(fileno(fd), &stv);
    
    buf =(char *) malloc(stv.st_size + 1);
    if (buf != NULL) {
        
        r = fread(buf,1,stv.st_size, fd);
        
        if (r == stv.st_size) {
            *ret_size = r;
            ret = buf;
        }
    }
    
    if (buf && buf != ret) free(buf);
    
    return ret;
}

int FileWrite(char *filename, char *data, int size) {
    int ret = 0;
    FILE *fd = NULL;
    
    unlink(filename);
    
    fd = fopen(filename, "wb");
    if (fd == NULL) return -1;
    
    if (fwrite(data, 1, size, fd) == size)
        ret = 1;
        
    fclose(fd);
    
    return ret;
}


int main(int argc, char *argv[]) {
    int i = 0;
    RSA *pubkey = NULL, *privkey = NULL;
    char *data_buf = NULL;
    int data_size = 0;
    
    char *signature_buf = NULL;
    int signature_size = 0;

    if (argc < 4) {
        printf("%s datafile pubkey signature_file [privkey]\n", argv[0]);
        exit(-1);
    }
        
    data_buf = FileContents(argv[1], &data_size);
    
    pubkey = LoadPublic(argv[2]);
    if (pubkey == NULL) {
        printf("Error loading pubkey\n");
        
        exit(-1);
    }
    
    // we only load the signature if we will NOT sign new
    if (argc != 5)
        signature_buf = FileContents(argv[3], &signature_size);
    
    if (argc == 5) {
        privkey = LoadPrivate(argv[4]);
        
        if (privkey == NULL) {
            printf("Error loading private key!\n");
            
            exit(-1);
        }
    }

    if (argc < 5) {
        i = SignCheck(pubkey, data_buf, data_size, signature_buf, signature_size);
        
        printf("signcheck(...) = %d\n", i);
    } else {
        // loaded priv key so we are signing new...
        signature_buf =(char *) calloc(1,4096);

        i = SignCreate(privkey, data_buf, data_size, signature_buf, &signature_size);
        
        printf("signcreate(...) = %d buf %X size: %d\n", i, signature_buf, signature_size);
        
        if (i == 1) {
            FileWrite(argv[3], signature_buf, signature_size);
        }
    }

    if (privkey != NULL)
        RSA_free(privkey);
    if (pubkey != NULL)
        RSA_free(pubkey);
        
    return 0;
}
