#ifndef CONFIDENTIALITY_COMPARE_H
#define CONFIDENTIALITY_COMPARE_H

#include <stddef.h>
#include <stdint.h>
#include "confidentiality.h"

CONFIDENTIALITY_INTERNAL
int constant_time_compare_uint64(uint64_t v);

CONFIDENTIALITY_INTERNAL
int constant_time_compare(const void *a, const void *b, size_t size);

CONFIDENTIALITY_INTERNAL
void wipe(void *buffer, size_t size);

#endif