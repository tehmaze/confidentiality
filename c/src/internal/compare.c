#include "internal/compare.h"

#define RANGE(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)

int constant_time_compare_uint64(uint64_t v)
{
    // constant time comparison to zero
    // return diff != 0 ? -1 : 0
    uint64_t x = (v >> 32) | ((uint32_t)v);
    return (1 & ((x - 1) >> 32)) - 1;
}

int constant_time_compare(const void *a, const void *b, size_t size)
{
    if (a == NULL) return 1;
    if (b == NULL) return -1;

    const uint8_t * ab = (const uint8_t *)a;
    const uint8_t * bb = (const uint8_t *)b;
    int diff;
    RANGE(i, 0, size) {
        diff |= constant_time_compare_uint64((uint64_t) (ab[i] ^ bb[i]));
    }
    return diff;
}

void wipe(void *buffer, size_t size)
{
    volatile uint8_t *ptr = (uint8_t*)buffer;
    RANGE(i, 0, size) {
        ptr[i] = 0x00;
    }
}