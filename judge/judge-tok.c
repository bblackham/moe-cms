/*
 *	A judge comparing two sequences of tokens
 *
 *	(c) 2007 Martin Krulis <bobrik@matfyz.cz>
 *	(c) 2007 Martin Mares <mj@ucw.cz>
 */

#include <stdio.h>
#include <string.h>

#include "judge.h"

static int trailing_nl(struct tokenizer *t)
{
  // Ignore empty lines at the end of file
  if (t->token[0])
    return 0;
  t->flags &= ~TF_REPORT_LINES;
  return !get_token(t);
}

int main(int argc, char **argv)
{
  struct tokenizer t1, t2;
  int report_lines = 1;

  if (argc != 3 && argc != 4)
    die("Usage: judge-tok [-n] <file1> <file2>");

  // Check for -n parameter
  report_lines = !(argc == 4 && !strcmp(argv[1], "-n"));

  tok_init(&t1, sopen_read(argv[argc-2]));
  tok_init(&t2, sopen_read(argv[argc-1]));
  if (report_lines)
    t1.flags = t2.flags = TF_REPORT_LINES;

  for (;;)
    {
      char *a = get_token(&t1), *b = get_token(&t2);
      if (!a)
	{
	  if (b && !trailing_nl(&t2))
	    tok_err(&t1, "Ends too early");
	  break;
	}
      else if (!b)
	{
	  if (a && !trailing_nl(&t1))
	    tok_err(&t2, "Garbage at the end");
	  break;
	}
      else if (strcmp(a, b))
	tok_err(&t1, "Found <%s>, expected <%s>", a, b);
    }

  return 0;
}
