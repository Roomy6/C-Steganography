#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* Arguments */
typedef struct {
    char hash_algo[16];
    char hashkey_algo[16];
    char hashkey_value[65];
    int amp;
} ArgumentOptions;

/* Error utility macro */
#define ON_ERROR_EXIT(cond, message) \
do { \
    if((cond)) { \
        printf("[!] Error in function: %s at line %d\n", __func__, __LINE__); \
        perror((message)); \
        exit(1); \
    } \
} while(0)

/* Check if a string "str" ends with a substring "ends" */
static inline bool str_ends_in(const char *str, const char *ends) {
    size_t str_len = strlen(str);
    size_t ends_len = strlen(ends);
    char *pos = strstr(str, ends);
    return (pos != NULL) && (pos + ends_len == str + str_len);
}

static int hexchar_to_int(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hexstr_to_bytes(const char *hexstr, unsigned char *bytes, size_t bytes_len) {
    size_t hex_len = strlen(hexstr);
    /* Ignore whitespace */
    while (hex_len > 0 && (hexstr[hex_len - 1] == '\n' || hexstr[hex_len - 1] == '\r' || hexstr[hex_len - 1] == ' ')) {
        hex_len--;
    }
    if (hex_len != bytes_len * 2) return -1;

    for (size_t i = 0; i < bytes_len; i++) {
        int hi = hexchar_to_int(hexstr[2 * i]);
        int lo = hexchar_to_int(hexstr[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        bytes[i] = (hi << 4) | lo;
    }
    return 0;
}
