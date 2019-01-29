#include <stdlib.h>
#include <string.h>
#include <stdio.h>

const char *getfield(char *line, int num)
{
    int row = 0;
    const char *tok = strtok(line, ":");
    while (tok != NULL)
    {
        printf("row %d: %s\n", row, tok);
        if (row >= num)
        {
            return tok;
        }
        tok = strtok(NULL, ":");
        row++;
    }
    return NULL;
}

char **split(char *s, size_t *n)
{
    static char tokens[16][128];
    //char **tokens = (char **) malloc(sizeof(char *) * 16);
    char *token;
    
    *n = 0;
    bzero(tokens, 16 * 128);

    token = strtok(s, ":");
    while (token) {
        memcpy(tokens[*n], token, strlen(token));
        token = strtok(NULL, ":");
        *n += 1;
    }

    return (char **)tokens;
}