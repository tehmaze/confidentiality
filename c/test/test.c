#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include "test.h"

char *get_vectors(char *line, int n)
{
    char *saved = NULL;
    char *token = strtok_r(line, ":", &saved);
    int i = 0;
    if (token == NULL || i == n) {
        return token;
    }
    i++;
    while (token != NULL) {
        printf("%d: %s\n", i - 1, token);
        token = strtok_r(NULL, ":", &saved);
        printf("+: %s\n", token);
        if (token == NULL || i == n) {
            return token;
        }
        i++;
    }
    return NULL;
}

static int decode_vector(test_vector *vector, char *buffer, size_t len)
{
    if (vector == NULL || buffer == NULL || len <= 0)
    {
        return 0;
    }

    // Working copy
    char *tmp = strdup(buffer); // , len);
    char *src = tmp;
    char *tok = NULL;

    // Wipe vector
    memset(vector, 0, sizeof(test_vector));

    // Split vectors and copy them into our struct
    while (src != NULL && (tok = strsep(&src, ":\n")) != NULL) {
        //printf("token %zu: %s; remains: %s\n", vector->size, tok, src);
        memcpy(vector->vector[vector->size++], tok, strlen(tok));
    }

    // Free working copy
    free(tmp);

    return 1;
}

int test_vectors(const char *name, int (*test)(test_vector *)) {
    static char *buffer = NULL;
    size_t n = 0;
    static test_vector vector;
    FILE *stream = fopen(name, "r");
    if (stream == NULL) {
        return 0;
    }

    while (getline(&buffer, &n, stream) > 0) {
        if (n == 0 || buffer[0] == '#') {
            continue;
        }
    
        if (decode_vector(&vector, buffer, n)) {
            if (!test(&vector)) {
                free(buffer);
                fclose(stream);
                return 0;
            }
        }

        // free(buffer);
    }

    return fclose(stream) == 0;
}

size_t unhex(char *dst, const char *src)
{
    size_t size = strlen(src);
    char x[3] = {0,};
    const char *tmp = src;
    char *out = dst;

    if (size == 0) {
       return 0;
    }
    if (size % 2) {
        size--;
    }

    
    dst = malloc((size >> 1) + 1);
    memset(dst, 0, (size >> 1) + 1);
    size_t parsed;
    for (parsed = 0; !(tmp[0] == 0x00 || tmp[1] == 0x00 || tmp[1] == '\n') && parsed < size; parsed += 2) {
        if (!(isxdigit(tmp[0]) && isxdigit(tmp[1]))) {
            errno = EINVAL;
            return parsed >> 1;
        }
        x[0] = tmp[0];
        x[1] = tmp[1];
        if (!strtoul(tmp, &dst, 16)) {
            errno = EINVAL;
            return parsed >> 1;
        }

        tmp += 2;
        dst += 1;
     }

     return parsed >> 1;
}