#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

int main (int argc, char *argv[]) {

  FILE *file;
  FILE *out;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  char *p;
  char *space;
  
  if (argc != 1) {
    return 1;
  }

  file = fopen(argv[1],"r");
  out = fopen(argv[2],"a+");

  if (!file || !out) {
    return 1;
  } 

  printf("File %s opened\n",argv[1]);
  printf("File %s opened\n",argv[2]);

  while ((read = getline(&line, &len, file)) != -1) {
    p = strstr(line,"__NR_");
    if (!p) {
      continue;
    }
    space = strchr(p,' ');
    if (!space) {
      continue;
    }
    space[0] = '\0';
    fprintf(out,"case %s: strcpy(info.name,\"%s\"); break;\n",p,&p[5]);
  }

  if (line) {
    free(line);
  }

  fclose(file);

  return 0;
}
