#include <stdio.h>
#include "test.h"

int test_suite(char *line)
{
  printf("line: %s", line);
  size_t i, n;
  char **vectors = split(line, &n);
  printf("%d fields\n", n);
  for (i = 0; i < n; i++) {
    printf("field %d: %s\n", i, vectors[i]);
  }

  return 1;
}
