#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define PIPEPATH "/tmp/targetpipe"

int main(void)
{
  writecmd(PIPEPATH, "%08x!");
  
  return 0;
}
// esp: 0xbfbf6710
// buf: 0xbfbf671d