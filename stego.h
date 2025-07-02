#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "image.h"

Image encode(const Image *img, const char *payload, bool is_file, int amplify_pixel_brightness);
char *decode_text(const Image *img);
uint8_t *decode_binary(const Image *img, size_t *out_size);
