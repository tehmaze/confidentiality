#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern int test_suite(char *);

int test_vectors(const char *filename)
{
  FILE *stream = fopen(filename, "r");
  if (stream == NULL) {
    perror("open");
    return 0;
  }

  char line[1024];
  while (fgets(line, 1024, stream)) {
    if (strlen(line) == 0 || line[0] == '#') {
      continue;
    }

    char *tmp = strdup(line);
    if (!test_suite(line))
    {
      free(tmp);
      return 0;
    }
    free(tmp);
  }

  return 1;
}

int main(int argc, char **argv)
{
  if (argc != 2)
  {
    fprintf(stderr, "usage: %s <vectors>\n", argv[0]);
    exit(1);
  }

  if (!test_vectors(argv[1])) {
    fprintf(stderr, "failed\n");
    return 1;
  }

  return 0;
}