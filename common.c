#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "common.h"

double
percentage(unsigned long long int n, unsigned long long int d)
{
  /* TBD: Error check here */
  long double percent = (long double)n / d * 100.0;
  return (double)percent;
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
grep_awk(FILE *fp, char *fstr, int nfield, char *delim)
{
  char *line = (char *)calloc(500, sizeof(char));
  check_mem(line);
  char *ret = NULL, *next_token = NULL;
  int i;
  while (fgets(line, 400, fp) != NULL) {
    if (strncasecmp(line, fstr, strlen(fstr)) == 0){
      ret = strtok_s(line, delim, &next_token);
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
  return NULL;
}  

char * 
squeeze(char *string, char *chars) 
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

char *
cpslib_strdup(char *s ) {
  char *result = (char*)malloc(strlen(s) + 1);
  if (result == (char*)0){return (char*)0;}
  strcpy(result, s);
  return result;
}

char* clean_errno() {
	static char buf[50];
	strerror_s(buf, 50, errno);
	return buf;
}
