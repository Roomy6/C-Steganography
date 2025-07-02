#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

void main() {
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    unsigned char md5_digest[MD5_DIGEST_LENGTH];
    unsigned char *buffer = "Hello world!";
    int i;

    SHA256(buffer, strlen(buffer), sha256_digest);
    MD5(buffer, strlen(buffer), md5_digest);

    printf("sha256: ");
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", sha256_digest[i]);
    }
    printf("\nmd5: ");
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", md5_digest[i]);
    }
    printf("\n");
}