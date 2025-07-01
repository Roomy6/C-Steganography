#pragma once
#include "image.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

Image encode(const Image *img, const char *payload, bool is_file);
char *decode_text(const Image *img);
uint8_t *decode_binary(const Image *img, size_t *out_size);
