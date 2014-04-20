#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

#include "common.h"



float
percentage(unsigned long int n, unsigned long int d)
{
  /* TBD: Error check here */
  float percent = ((float)n / (float)d)*100.0;
  return percent;
}


int
str_comp(const void *key, const void *memb)
{
  const char **a = (const char **)key;
  const char **b = (const char **)memb;
  return strcmp(*a, *b);
}

int
int_comp(const void *key, const void *memb)
{
  const int a = *(int *)key;
  const int b = *(int *)memb;
  if (a == b)
    return 0;
  else
    return -1;
}


char *
grep_awk(FILE *fp, const char *fstr, int nfield, const char *delim)
{
  char *line = (char *)calloc(500, sizeof(char));
  check_mem(line);
  char *ret = NULL;
  int i;
  while (fgets(line, 400, fp) != NULL) {
    if (strncasecmp(line, fstr, strlen(fstr)) == 0){
      ret = strtok(line, delim);
      for (i = 0; i < nfield; i++) {
        ret = strtok(NULL, delim);
      }
      if (ret) {
        ret = strdup(ret);
        check_mem(ret);
        free(line);
        return ret;
      }
    }
  }
  free(line);
  return NULL;
 error:
  if(line) free(line);
  return NULL;
}

char * /* Removes every char in chars from string */
squeeze(char *string, const char *chars)
{
  char *src = string;
  char *target = string;
  char ch;
  for(;*chars; chars++) {
    ch =*chars;
    src = string;
    target = string;
    while(*src != '\0') {
      if (*src != ch) {
        *target = *src;
        target++;
       }
      src++;
    }
    *target='\0';
  }
  return string;
}

/* Used to apply qsort to an array of strings */
int str_cmp(const void *a, const void *b)  { 
  const char **na = (const char **)a;
  const char **nb = (const char **)b;
  return strcmp(*na, *nb);
} 

char* skip_whitespaces(char *pos) {
  while(isspace(pos)) pos++;
  return pos;
}
