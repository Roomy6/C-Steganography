#include "stego.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

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

/* Encoding fuction */
Image encode(const Image *img, const char *payload, bool is_file) {
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
        payload_bytes = len + 1;                        /* Adding the null terminator to know when to stop decoding process */
        data = malloc(payload_bytes);
        memcpy(data, payload, len);
        data[len] = '\0';
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
    }

    /* Write the payload bits */
    size_t bit_index = 32;
    for (size_t i = 0; i < payload_bytes; ++i) {
        for (int b = 7; b >= 0; --b) {
            uint8_t bit = (data[i] >> b) & 1;
            flat[bit_index++] = (flat[bit_index] & ~1) | bit;
        }
    }

    free(data);
    return result;
}

/* Decoding text */
char *decode_text(const Image *img) {
    uint8_t *flat = img->data;
    uint8_t length_bits[32];

    for (size_t i = 0; i < 32; ++i) {
        length_bits[i] = flat[i] & 1;
    }
    uint32_t byte_len = bits_to_int(length_bits, 32);
    size_t total_bits = byte_len * 8;

    char *out = malloc(byte_len + 1);
    size_t bit_index = 32;

    for (uint32_t i = 0; i < byte_len; ++i) {
        uint8_t byte = 0;
        for (int b = 7; b >= 0; --b) {
            byte = (byte << 1) | (flat[bit_index++] & 1);
        }
        out[i] = byte;
    }
    out[byte_len] = '\0';
    return out;
}

/* Decode binary to int */
uint8_t *decode_binary(const Image *img, size_t *out_size) {
    uint8_t *flat = img->data;
    uint8_t length_bits[32];

    for (size_t i = 0; i < 32; ++i) {
        length_bits[i] = flat[i] & 1;
    }
    uint32_t byte_len = bits_to_int(length_bits, 32);
    *out_size = byte_len;
    uint8_t *out = malloc(byte_len);
    size_t bit_index = 32;

    for (uint32_t i = 0; i < byte_len; ++i) {
        uint8_t byte = 0;
        for (int b = 7; b >= 0; --b) {
            byte = (byte << 1) | (flat[bit_index++] & 1);
        }
        out[i] = byte;
    }
    return out;
}
