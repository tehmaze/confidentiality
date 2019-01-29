#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "test.h"

static char default_vectors[] = "../../testdata/authentication-vectors.txt";

int test(test_vector *vector)
{
    if (vector == NULL)
    {
        return 0;
    }

    size_t key_len = strlen(vector->vector[1]) >> 1;
    size_t msg_len = strlen(vector->vector[2]) >> 1;
    size_t tmp;
    char *key = malloc(key_len);
    char *msg = malloc(msg_len);
    char signature[32];
    if ((tmp = unhex(key, vector->vector[1])) != key_len) {
        printf("test: %s, error: unexpected key size, expected %zu, got %zu\n", 
            vector->vector[0], key_len, tmp);
        return 0;
    }
    if ((tmp = unhex(msg, vector->vector[2])) != msg_len) {
        printf("test: %s, error: unexpected message size, expected %zu, got %zu\n", 
            vector->vector[0], msg_len, tmp);
        return 0;
    }
    if ((tmp = unhex(signature, vector->vector[3])) != 32) {
        printf("test: %s, error: unexpected signature size, expected %zu, got %zu\n", 
            vector->vector[0], 32UL, tmp);
        return 0;
    }
    
    printf("test: %s, key: %zu, msg: %zu\n", vector->vector[0], key_len, msg_len);

    return 1;
}

int main(int argc, char **argv)
{
    char *name = default_vectors;
    if (argc > 1) {
        name = argv[1];
    }
    if (!test_vectors(name, test)) {
        fprintf(stderr, "errno: %d, ", errno);
        perror("error:");
        fprintf(stderr, "\n");
        return 1;
    }
    return 0;
}