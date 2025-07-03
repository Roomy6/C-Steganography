#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "stego.h"
#include "utils.h"

/* Convert the int to bit values */
static void int_to_bits(uint32_t value, uint8_t *bits, size_t bit_len) {
    for (int i = bit_len - 1; i >= 0; --i) {
        bits[i] = value & 1;
        value >>= 1;
    }
}

/* Convert bits to int */
static uint32_t bits_to_int(const uint8_t *bits, size_t bit_len) {
    uint32_t value = 0;
    for (size_t i = 0; i < bit_len; ++i) {
        value = (value << 1) | (bits[i] & 1);
    }
    return value;
}

/*
                        !!! WARNING !!!
                THIS CODE IS AWFULL AND LOOKS UGLY!
        I am in the process of cleaning it up the best I can.
        I just wanted to realease this before I mess something up.
*/

/* Encoding fuction */
Image encode(const Image *img, const char *payload, bool is_file, const char *hash_algo, int amplify_pixel_brightness) {
    size_t payload_bytes = 0;
    uint8_t *data = NULL;

    /* Load payload into bit array */
    if (is_file) {
        FILE *f = fopen(payload, "rb");
        ON_ERROR_EXIT(f == NULL, "Unable to open payload file");

        fseek(f, 0, SEEK_END);
        payload_bytes = ftell(f);
        fseek(f, 0, SEEK_SET);

        data = malloc(payload_bytes);
        fread(data, 1, payload_bytes, f);
        fclose(f);
    } else {
        size_t len = strlen(payload);
        payload_bytes = len + 1;
        data = malloc(payload_bytes);
        memcpy(data, payload, len);
        data[len] = '\0';                           /* Adding the null terminator to know when to stop decoding process */
    }

    /* Check what hash method was provided */
    /* This code took WAY too long haha */
    if (hash_algo != NULL && strlen(hash_algo) > 0) {
        if (strcmp(hash_algo, "sha256") == 0) {
            char filename[32];
            uint32_t seed;

            snprintf(filename, sizeof(filename), "hash.%s", hash_algo);
            FILE *fHash = fopen(filename, "w");
            if (!fHash) {
                perror("Failed to open hash output file");
                exit(1);
            }

            unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
            SHA256(data, payload_bytes, sha256_digest);
            memcpy(&seed, sha256_digest, sizeof(seed));
            srand(seed);

            printf("sha256: ");
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                fprintf(fHash, "%02x", sha256_digest[i]);
                printf("%02x", sha256_digest[i]);
            }
            printf("\n");
            printf("seed: %d\n", seed);
        } else if (strcmp(hash_algo, "md5") == 0) {
            char filename[32];
            uint32_t seed = 0;

            snprintf(filename, sizeof(filename), "hash.%s", hash_algo);
            FILE *fHash = fopen(filename, "w");
            if (!fHash) {
                perror("Failed to open hash output file");
                exit(1);
            }

            unsigned char md5_digest[MD5_DIGEST_LENGTH];
            MD5(data, payload_bytes, md5_digest);
            memcpy(&seed, md5_digest, sizeof(seed));
            srand(seed);
            printf("md5: ");
            for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
                fprintf(fHash, "%02x", md5_digest[i]);
                printf("%02x", md5_digest[i]);
            }
            printf("\n");
        } else {
            ON_ERROR_EXIT(1, "Invalid hashing algorithm provided.");
        }
    }

    size_t total_bits = 32 + payload_bytes * 8;
    ON_ERROR_EXIT(total_bits > img->size, "Payload too large for image");

    Image result;
    Image_create(&result, img->width, img->height, img->channels, false);
    memcpy(result.data, img->data, img->size);

    uint8_t *flat = result.data;

    /* Write a 32-bit lenght header */
    uint8_t length_bits[32];
    int_to_bits((uint32_t)payload_bytes, length_bits, 32);
    for (size_t i = 0; i < 32; ++i) {
        flat[i] = (flat[i] & ~1) | length_bits[i];
        if (length_bits[i] == 1 && flat[i] < 240) flat[i] += amplify_pixel_brightness;

    }

    size_t usable_pixels = img->size - 32;
    size_t total_payload_bits = payload_bytes * 8;

    ON_ERROR_EXIT(total_payload_bits > usable_pixels, "Payload too large for image (random bit mode)");

    /* Determine if hashing is used */
    bool use_random = (hash_algo != NULL && strlen(hash_algo) > 0);

    if (use_random) {
        /* Prepare positions array for random writing */
        size_t usable_pixels = img->size - 32;
        int *positions = malloc(sizeof(int) * usable_pixels);
        for (size_t i = 0; i < usable_pixels; ++i)
            positions[i] = 32 + i;

        /* Shuffle based on seeded rand() */
        for (size_t i = usable_pixels - 1; i > 0; --i) {
            size_t j = rand() % (i + 1);
            int tmp = positions[i];
            positions[i] = positions[j];
            positions[j] = tmp;
        }

        /* Write payload bits in pseudo-random order */
        size_t bit_written = 0;
        for (size_t i = 0; i < payload_bytes; ++i) {
            for (int b = 7; b >= 0; --b) {
                uint8_t bit = (data[i] >> b) & 1;
                size_t pos = positions[bit_written++];
                flat[pos] = (flat[pos] & ~1) | bit;
                if (bit == 1 && flat[pos] < 240)
                    flat[pos] += amplify_pixel_brightness;
            }
        }
        free(positions);

    } else {
        /* Normal sequential writing without hashing */
        size_t bit_index = 32;
        for (size_t i = 0; i < payload_bytes; ++i) {
            for (int b = 7; b >= 0; --b) {
                uint8_t bit = (data[i] >> b) & 1;
                flat[bit_index] = (flat[bit_index] & ~1) | bit;
                if (bit == 1 && flat[bit_index] < 240)
                    flat[bit_index] += amplify_pixel_brightness;
                bit_index++;
            }
        }
    }

    free(data);
    return result;
}

/* Decoding text */
char *decode_text(const Image *img, const char *hashkey_algo, const char *hashkey_value) {
    uint8_t *flat = img->data;
    uint8_t length_bits[32];

    /* Read the 32-bit length header */
    for (size_t i = 0; i < 32; ++i)
        length_bits[i] = flat[i] & 1;

    uint32_t byte_len = bits_to_int(length_bits, 32);
    char *out = malloc(byte_len + 1);
    size_t bit_used = 0;

    bool use_hash = (hashkey_algo && strlen(hashkey_algo) > 0);
    uint32_t seed = 0;

    if (use_hash) {
        printf("Hash key input string (%zu chars): '%s'\n", strlen(hashkey_value), hashkey_value);

        if (strcmp(hashkey_algo, "sha256") == 0) {
            unsigned char raw_hash[SHA256_DIGEST_LENGTH];
            if (hexstr_to_bytes(hashkey_value, raw_hash, SHA256_DIGEST_LENGTH) != 0) {
                fprintf(stderr, "Invalid SHA256 hash key format.\n");
                exit(1);
            }
            memcpy(&seed, raw_hash, sizeof(seed));
        } else if (strcmp(hashkey_algo, "md5") == 0) {
            unsigned char raw_hash[MD5_DIGEST_LENGTH];
            if (hexstr_to_bytes(hashkey_value, raw_hash, MD5_DIGEST_LENGTH) != 0) {
                fprintf(stderr, "Invalid MD5 hash key format.\n");
                exit(1);
            }
            memcpy(&seed, raw_hash, sizeof(seed));
        } else {
            fprintf(stderr, "Unsupported hash algorithm.\n");
            exit(1);
        }

        srand(seed);
        printf("Seed: %u\n", seed);

        /* Generate shuffled positions */
        size_t usable_bits = img->size - 32;
        int *positions = malloc(sizeof(int) * usable_bits);
        for (size_t i = 0; i < usable_bits; ++i)
            positions[i] = 32 + i;

        for (size_t i = usable_bits - 1; i > 0; --i) {
            size_t j = rand() % (i + 1);
            int tmp = positions[i];
            positions[i] = positions[j];
            positions[j] = tmp;
        }

        /* Extract data in shuffled order */
        for (uint32_t i = 0; i < byte_len; ++i) {
            uint8_t byte = 0;
            for (int b = 7; b >= 0; --b) {
                int pos = positions[bit_used++];
                byte = (byte << 1) | (flat[pos] & 1);
            }
            out[i] = byte;
        }

        free(positions);
    } else {
        /* Sequential decoding */
        size_t bit_index = 32;
        for (uint32_t i = 0; i < byte_len; ++i) {
            uint8_t byte = 0;
            for (int b = 7; b >= 0; --b)
                byte = (byte << 1) | (flat[bit_index++] & 1);
            out[i] = byte;
        }
    }

    out[byte_len] = '\0';
    return out;
}

/* Decode binary to int */
uint8_t *decode_binary(const Image *img, const char *hashkey_algo, const char *hashkey_value, size_t *out_size) {
    uint8_t *flat = img->data;
    uint8_t length_bits[32];

    /* Read the 32-bit length header */
    for (size_t i = 0; i < 32; ++i)
        length_bits[i] = flat[i] & 1;

    uint32_t byte_len = bits_to_int(length_bits, 32);
    *out_size = byte_len;

    uint8_t *out = malloc(byte_len);
    size_t bit_used = 0;

    bool use_hash = (hashkey_algo && strlen(hashkey_algo) > 0);
    uint32_t seed = 0;

    if (use_hash) {
        printf("Hash key input string (%zu chars): '%s'\n", strlen(hashkey_value), hashkey_value);

        if (strcmp(hashkey_algo, "sha256") == 0) {
            unsigned char raw_hash[SHA256_DIGEST_LENGTH];
            if (hexstr_to_bytes(hashkey_value, raw_hash, SHA256_DIGEST_LENGTH) != 0) {
                fprintf(stderr, "Invalid SHA256 hash key format.\n");
                exit(1);
            }
            memcpy(&seed, raw_hash, sizeof(seed));
        } else if (strcmp(hashkey_algo, "md5") == 0) {
            unsigned char raw_hash[MD5_DIGEST_LENGTH];
            if (hexstr_to_bytes(hashkey_value, raw_hash, MD5_DIGEST_LENGTH) != 0) {
                fprintf(stderr, "Invalid MD5 hash key format.\n");
                exit(1);
            }
            memcpy(&seed, raw_hash, sizeof(seed));
        } else {
            fprintf(stderr, "Unsupported hash algorithm.\n");
            exit(1);
        }

        srand(seed);
        printf("Seed: %u\n", seed);

        /* Generate shuffled positions */
        size_t usable_bits = img->size - 32;
        int *positions = malloc(sizeof(int) * usable_bits);
        for (size_t i = 0; i < usable_bits; ++i)
            positions[i] = 32 + i;

        for (size_t i = usable_bits - 1; i > 0; --i) {
            size_t j = rand() % (i + 1);
            int tmp = positions[i];
            positions[i] = positions[j];
            positions[j] = tmp;
        }

        /* Extract data in shuffled order */
        for (uint32_t i = 0; i < byte_len; ++i) {
            uint8_t byte = 0;
            for (int b = 7; b >= 0; --b) {
                int pos = positions[bit_used++];
                byte = (byte << 1) | (flat[pos] & 1);
            }
            out[i] = byte;
        }

        free(positions);
    } else {
        /* Sequential decoding */
        size_t bit_index = 32;
        for (uint32_t i = 0; i < byte_len; ++i) {
            uint8_t byte = 0;
            for (int b = 7; b >= 0; --b)
                byte = (byte << 1) | (flat[bit_index++] & 1);
            out[i] = byte;
        }
    }
    return out;
}
