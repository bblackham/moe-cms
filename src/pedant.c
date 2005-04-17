/*
 *	A Pedantic Check of Text Input/Output File Syntax
 *
 *	(c) 2005 Martin Mares <mj@ucw.cz>
 */

#include <stdio.h>

int main(void)
{
  int line = 1;
  int pos = 0;
  int maxlen = 0;
  int lastlen = -1;
  int space = 0;
  int c;
  while ((c = getchar()) >= 0)
    {
      if (c == '\n')
	{
	  if (space)
	    printf("Line %d: Trailing spaces\n", line);
	  if (line == 1 && !pos)
	    printf("Line %d: Leading empty line\n", line);
	  if (maxlen < pos)
	    maxlen = pos;
	  if (!lastlen && !pos)
	    printf("Line %d: Consecutive empty lines\n", line);
	  lastlen = pos;
	  line++;
	  pos = space = 0;
	}
      else
	{
	  if (c == ' ')
	    {
	      if (!pos)
		printf("Line %d: Leading spaces\n", line);
	      if (space)
		printf("Line %d: Consecutive spaces\n", line);
	      space = 1;
	    }
	  else
	    {
	      space = 0;
	      if (c < ' ' || c >= 0x7f)
		printf("Line %d: Invalid character 0x%02x\n", line, c);
	    }
	  pos++;
	}
    }
  if (pos)
    printf("Line %d: Incomplete line at the end of file\n", line);
  else if (!lastlen)
    printf("Line %d: Trailing empty line\n", line-1);
  printf("Found %d lines, the longest has %d chars\n", line-1, maxlen);
  return 0;
}
