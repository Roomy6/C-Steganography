#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "image.h"
#include "utils.h"
#include "stego.h"

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  Encode: %s encode <input_image> <output_image> <text|file> <payload>\n", argv[0]);
        fprintf(stderr, "  Decode: %s decode <input_image> <output_file> <text|file>\n", argv[0]);
        return 1;
    }

    /* Check argument entries */
    Image img;
    if (strcmp(argv[1], "encode") == 0) {
        const char *input_image = argv[2];
        const char *output_image = argv[3];
        const char *mode = argv[4];
        const char *payload = argv[5];

        Image_load(&img, input_image);
        ON_ERROR_EXIT(img.data == NULL, "Failed to load input image");

        bool is_file = strcmp(mode, "file") == 0;
        Image encoded = encode(&img, payload, is_file);
        Image_save(&encoded, output_image);
        Image_free(&img);
        Image_free(&encoded);
        printf("Encoding complete. Output saved to %s\n", output_image);
    }
    else if (strcmp(argv[1], "decode") == 0) {
        const char *input_image = argv[2];
        const char *output_path = argv[3];
        const char *mode = argv[4];

        bool as_text = strcmp(mode, "text") == 0;

        Image_load(&img, input_image);
        ON_ERROR_EXIT(img.data == NULL, "Failed to load encoded image");

        if (as_text) {
            char *decoded = decode_text(&img);
            printf("Decoded message:\n%s\n", decoded);
            free(decoded);
        } else {
            size_t out_size;
            uint8_t *data = decode_binary(&img, &out_size);
            FILE *fp = fopen(output_path, "wb");
            fwrite(data, 1, out_size, fp);
            fclose(fp);
            free(data);
            printf("Decoded binary written to %s\n", output_path);
        }
        Image_free(&img);
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
