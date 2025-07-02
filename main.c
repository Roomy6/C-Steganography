#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "image.h"
#include "utils.h"
#include "stego.h"

int main(int argc, char *argv[]) {
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  Encode: %s encode <input_image> <output_image> <text|file> <payload>\n", argv[0]);
        fprintf(stderr, "  Decode: %s decode <input_image> <output_file> <text|file>\n", argv[0]);

        printf("\n-----[ Additional Arguments ]-----\n\n");

        //printf("  --hash [md5, sha256]              Utilise file/text hashing for random data placement.\n");
        //printf("  --hashkey [md5, sha256] [key]     Utilise file/text hashing for random data placement.\n");
        printf("  --amp [int]                       Amplify pixel brightnet of the encoded data.\n");
        //printf("  --encrypt [a, b]                Encrypt the data for better protection.\n");
        return 1;
    }

    /* Check argument entries */
    Image img;
    if (strcmp(argv[1], "encode") == 0) {
        const char *input_image = argv[2];
        const char *output_image = argv[3];
        const char *mode = argv[4];
        const char *payload = argv[5];

        ArgumentOptions options = { .hash_algo = "", .hashkey_algo = "", .hashkey_value = "", .amp = 0 };

        for (int i = 6; i < argc; i++) {
            if (strcmp(argv[i], "--hash") == 0 && i + 1 < argc) {
                strncpy(options.hash_algo, argv[i + 1], sizeof(options.hash_algo) - 1);
                i++;
            } else if (strcmp(argv[i], "--hashkey") == 0 && i + 2 < argc) {
                strncpy(options.hashkey_algo, argv[i + 1], sizeof(options.hashkey_algo) - 1);
                strncpy(options.hashkey_value, argv[i + 2], sizeof(options.hashkey_value) - 1);
                i += 2;
            } else if (strcmp(argv[i], "--amp") == 0 && i + 1 < argc) {
                options.amp = atoi(argv[i + 1]);
                i++;
            } else {
                fprintf(stderr, "Unknown or malformed option: %s\n", argv[i]);
            }
        }

        Image_load(&img, input_image);
        ON_ERROR_EXIT(img.data == NULL, "Failed to load input image");

        bool is_file = strcmp(mode, "file") == 0;
        Image encoded = encode(&img, payload, is_file, options.amp);
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
            /* Export the encoded text data to a file */
            char *data = decode_text(&img);
            //size_t out_size = sizeof(data); /* Will only output 8 bits(bytes?) of text */
            //printf("Output size: %ld\n", out_size);
            size_t out_size = strlen(data); /* Instead get the string length (could of guessed that lol) */
            printf("Decoded message:\n%s\n", data);
            FILE *fp = fopen(output_path, "wb");
            fwrite(data, 1, out_size, fp);
            fclose(fp);
            free(data);
        } else {
            /* Export the encoded binary data to a binary file */
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
        printf("Use argument --help to get a list of options.\n");
        return 1;
    }

    return 0;
}
