#include <stdio.h>

#include "judge.h"

int main(void)
{
  struct stream *i = sopen_fd("stdin", 0);

  struct tokenizer t;
  tok_init(&t, i);
  // t.maxtoken = 1000;
  t.flags = TF_REPORT_LINES;
  char *tok;
  while (tok = get_token(&t))
    {
      printf("<%s>", tok);
#define T(f, type, fmt) { type x; if (to_##f(&t, &x)) printf(" = " #f " " fmt, x); }
      T(int, int, "%d");
      T(uint, unsigned int, "%u");
      T(long, long int, "%ld");
      T(ulong, unsigned long int, "%lu");
      T(double, double, "%f");
      T(long_double, long double, "%Lf");
#undef T
      putchar('\n');
    }
  tok_cleanup(&t);

  sclose(i);
  return 0;
}
