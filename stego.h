#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include "image.h"

Image encode(const Image *img, const char *payload, bool is_file, const char *hash_algo, const int amplify_pixel_brightness);
char *decode_text(const Image *img, const char *hashkey_algo, const char *hashkey_value);
uint8_t *decode_binary(const Image *img, const char *hashkey_algo, const char *hashkey_value, size_t *out_size);
