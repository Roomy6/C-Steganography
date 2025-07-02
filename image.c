#include <math.h>

#include "image.h"
#include "utils.h"

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image/stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image/stb_image_write.h"

void Image_load(Image *img, const char *frame) {
    if((img->data = stbi_load(frame, &img->width, &img->height, &img->channels, 0)) != NULL) {
        img->size = img->width * img->height * img->channels;
        img->allocation_ = STB_ALLOCATED;
    }
}

void Image_create(Image *img, int with, int height, int channels, bool zeroed) {
    size_t size = with * height * channels;
    if(zeroed) {
        img->data = calloc(size, 1);
    } else {
        img->data = malloc(size);
    }

    if(img->data != NULL) {
        img->width = with;
        img->height = height;
        img->size = size;
        img->channels = channels;
        img->allocation_ = SELF_ALLOCATED;
    }
}

/* Make sure to use a lossless image format, jpg will NOT decode the file */
void Image_save(const Image *img, const char *frame) {
    if(str_ends_in(frame, ".png") || str_ends_in(frame, ".PNG")) {
        stbi_write_png(frame, img->width, img->height, img->channels, img->data, img->width * img->channels);
    } else if(str_ends_in(frame, ".bmp") || str_ends_in(frame, ".BMP")) {
        stbi_write_bmp(frame, img->width, img->height, img->channels, img->data);
    } else {
        fprintf(stderr, "[!] Refusing to save lossy file: %s\n", frame);
        fprintf(stderr, "    Use a lossless format like .png or .bmp\n");
        exit(1);
    }
}

void Image_free(Image *img) {
    if(img->allocation_ != NO_ALLOCATION && img->data != NULL) {
        if(img->allocation_ == STB_ALLOCATED) {
            stbi_image_free(img->data);
        } else {
            free(img->data);
        }
        img->data = NULL;
        img->width = 0;
        img->height = 0;
        img->size = 0;
        img->allocation_ = NO_ALLOCATION;
    }
}