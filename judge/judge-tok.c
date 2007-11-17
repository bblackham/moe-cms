/*
 *	A judge comparing two sequences of tokens
 *
 *	(c) 2007 Martin Krulis <bobrik@matfyz.cz>
 *	(c) 2007 Martin Mares <mj@ucw.cz>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "judge.h"

static int ignore_nl, ignore_trailing_nl;

static int trailing_nl(struct tokenizer *t)
{
  // Ignore empty lines at the end of file
  if (t->token[0] || !ignore_trailing_nl)
    return 0;
  t->flags &= ~TF_REPORT_LINES;
  return !get_token(t);
}

static void usage(void)
{
  fprintf(stderr, "Usage: judge-tok [<options>] <file1> <file2>\n\
\n\
Options:\n\
-n\t\tIgnore newlines\n\
-t\t\tIgnore newlines at the end of file\n\
");
  exit(2);
}

int main(int argc, char **argv)
{
  struct tokenizer t1, t2;
  int opt;

  while ((opt = getopt(argc, argv, "nt")) >= 0)
    switch (opt)
      {
      case 'n':
	ignore_nl++;
	break;
      case 't':
	ignore_trailing_nl++;
	break;
      default:
	usage();
      }
  if (optind + 2 != argc)
    usage();

  tok_init(&t1, sopen_read(argv[optind]));
  tok_init(&t2, sopen_read(argv[optind+1]));
  if (!ignore_nl)
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
