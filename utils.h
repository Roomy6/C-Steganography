#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* Arguments */
typedef struct {
    char hash_algo[16];
    char hashkey_algo[16];
    char hashkey_value[64];
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