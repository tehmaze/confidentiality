#ifndef CONFIDENTIALITY_TEST_H
#define CONFIDENTIALITY_TEST_H

#include <stddef.h>

typedef struct {
    size_t size;
    char vector[16][256];
} test_vector;

char *get_vector(char *line, int n);
int test_vectors(const char *name, int (*test)(test_vector *));

size_t unhex(char *dst, const char *src);

#endif