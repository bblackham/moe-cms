/*
 *  The Submit Daemon: Tasks
 *
 *  (c) 2007 Martin Mares <mj@ucw.cz>
 */

#include "lib/lib.h"
#include "lib/conf.h"
#include "lib/stkstring.h"

#include <sys/stat.h>

#include "submitd.h"

clist task_list;

static byte *
tasks_conf_init(void)
{
  clist_init(&task_list);
  return NULL;
}

static struct cf_section task_conf = {
  CF_TYPE(struct task),
  CF_ITEMS {
    CF_STRING("Name", PTR_TO(struct task, name)),
    CF_END
  }
};

struct cf_section tasks_conf = {
  CF_INIT(tasks_conf_init),
  CF_ITEMS {
    CF_LIST("Task", &task_list, &task_conf),
    CF_END
  }
};

struct task *
task_find(byte *name)
{
  CLIST_FOR_EACH(struct task *, t, task_list)
    if (!strcasecmp(t->name, name))
      return t;
  return NULL;
}

int
user_exists_p(byte *user)
{
  byte *fn = stk_printf("solutions/%s/status", user);
  struct stat st;
  return !stat(fn, &st) && S_ISREG(st.st_mode);
}
