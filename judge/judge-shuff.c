/*
 *	A judge comparing shuffled sequences of tokens
 *
 *	(c) 2007 Martin Krulis <bobrik@matfyz.cz>
 *	(c) 2007 Martin Mares <mj@ucw.cz>
 *
 *	FIXME: INCOMPLETE!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <math.h>

#include "judge.h"

static int ignore_nl, ignore_empty, ignore_case;
static int shuffle_lines, shuffle_words;

/*** Token buffer ***/

struct tokpage {
  struct tokpage *next;
  char *pos, *end;
  char buf[];
};

struct tokbuf {
  // For writing:
  struct tokpage *first_page, *last_page;
  unsigned int num_tokens;
  // For reading:
  struct tokpage *this_page;
  char *read_pos;
};

#define TOKBUF_PAGE 256

static void init_tokbuf(struct tokbuf *tb)
{
  memset(tb, 0, sizeof(*tb));
}

static void add_token(struct tokbuf *tb, char *token, int l)
{
  l++;
  struct tokpage *pg = tb->last_page;
  if (!pg || pg->end - pg->pos < l)
    {
      int size = TOKBUF_PAGE - sizeof(struct tokbuf);
      if (l > size/5)
	size = l;
      pg = xmalloc(sizeof(struct tokbuf) + size);
      if (tb->last_page)
	tb->last_page->next = pg;
      else
	tb->first_page = pg;
      tb->last_page = pg;
      pg->next = NULL;
      pg->pos = pg->buf;
      pg->end = pg->buf + size;
    }
  memcpy(pg->pos, token, l);
  pg->pos += l;
  tb->num_tokens++;
}

static char *get_next(struct tokbuf *tb)
{
  struct tokpage *pg = tb->this_page;
  tb->read_pos += strlen(tb->read_pos) + 1;
  if (tb->read_pos >= pg->end)
    {
      tb->this_page = pg = pg->next;
      if (!pg)
	return NULL;
      tb->read_pos = pg->buf;
    }
  return tb->read_pos;
}

static char *get_first(struct tokbuf *tb)
{
  struct tokpage *pg = tb->first_page;
  if (!pg)
    return NULL;
  tb->this_page = pg;
  tb->read_pos = pg->buf;
  return pg->buf;
}

/*** Reading of input ***/

struct tok {
  char *token;
  unsigned int hash;
};

struct line {
  struct tok *toks;
  unsigned int num_toks;
  unsigned int hash;
};

struct shouffle {
  struct tokbuf tb;
  struct tok *tok_array;
  struct line *line_array;
  unsigned int num_lines;
};

static void read_input(struct tokenizer *t, struct tokbuf *tb)
{
  char *tok;
  int nl = 1;

  init_tokbuf(tb);
  while (tok = get_token(t))
    {
      if (tok[0])
	nl = 0;
      else
	{
	  if (nl && ignore_nl)
	    continue;
	  nl = 1;
	}
      add_token(tb, tok, t->toksize);
    }
  if (!nl)
    add_token(tb, "", 0);
}

static void slurp(struct tokenizer *t, struct shouffle *s)
{
}

/*** Main ***/

static void usage(void)
{
  fprintf(stderr, "Usage: judge-shuff [<options>] <output> <correct>\n\
\n\
Options:\n\
-n\t\tIgnore newlines and match the whole input as a single line\n\
-e\t\tIgnore empty lines\n\
-l\t\tShuffle lines (i.e., ignore their order)\n\
-w\t\tShuffle words in each line\n\
-i\t\tIgnore case\n\
");
  exit(2);
}

int main(int argc, char **argv)
{
  struct tokenizer t1, t2;
  int opt;

  while ((opt = getopt(argc, argv, "nelwi")) >= 0)
    switch (opt)
      {
      case 'n':
	ignore_nl++;
	break;
      case 'e':
	ignore_empty++;
	break;
      case 'l':
	shuffle_lines++;
	break;
      case 'w':
	shuffle_words++;
	break;
      case 'i':
	ignore_case++;
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

  struct tokbuf b1;
  read_input(&t1, &b1);

  return 0;
}
