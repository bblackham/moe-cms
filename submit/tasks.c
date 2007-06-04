/*
 *  The Submit Daemon: Tasks
 *
 *  (c) 2007 Martin Mares <mj@ucw.cz>
 */

#include "lib/lib.h"
#include "lib/conf.h"
#include "lib/fastbuf.h"
#include "lib/stkstring.h"
#include "sherlock/object.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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

void
task_lock_status(struct conn *c)
{
  ASSERT(!c->task_lock_fd);
  if ((c->task_lock_fd = open(stk_printf("solutions/%s/status.lock", c->user), O_RDWR | O_CREAT | O_TRUNC, 0666)) < 0)
    die("Cannot create task lock: %m");
  struct flock fl = {
    .l_type = F_WRLCK,
    .l_whence = SEEK_SET,
    .l_start = 0,
    .l_len = 1
  };
  if (fcntl(c->task_lock_fd, F_SETLKW, &fl) < 0)
    die("Cannot lock status file: %m");

  struct fastbuf *fb = bopen_try(stk_printf("solutions/%s/status", c->user), O_RDONLY, 4096);
  c->task_status = obj_new(c->pool);
  if (fb)
    {
      obj_read(fb, c->task_status);
      bclose(fb);
    }
}

void
task_unlock_status(struct conn *c, uns write_back)
{
  ASSERT(c->task_lock_fd);
  ASSERT(c->task_status);

  if (write_back)
    {
      struct fastbuf *fb = bopen_tmp(4096);
      obj_write(fb, c->task_status, BUCKET_TYPE_PLAIN);
      brewind(fb);
      bconfig(fb, BCONFIG_IS_TEMP_FILE, 0);
      byte *name = stk_printf("solutions/%s/status", c->user);
      if (rename(fb->name, name) < 0)
	die("Unable to rename %s to %s: %m", fb->name, name);
      bclose(fb);
    }

  struct flock fl = {
    .l_type = F_UNLCK,
    .l_whence = SEEK_SET,
    .l_start = 0,
    .l_len = 1
  };
  if (fcntl(c->task_lock_fd, F_SETLKW, &fl) < 0)
    die("Cannot unlock status file: %m");
  c->task_lock_fd = 0;
  c->task_status = NULL;
}

struct odes *
task_status_find_task(struct conn *c, struct task *t)
{
  for (struct oattr *a = obj_find_attr(c->task_status, 'T' + OBJ_ATTR_SON); a; a=a->same)
    {
      struct odes *o = a->son;
      byte *name = obj_find_aval(o, 'T');
      if (!strcmp(name, t->name))
	return o;
    }
  struct odes *o = obj_add_son(c->task_status, 'T' + OBJ_ATTR_SON);
  obj_set_attr(o, 'T', t->name);
  return o;
}

void
task_submit(struct conn *c, struct task *t, struct fastbuf *fb, byte *filename)
{
  byte *dir = stk_printf("solutions/%s/%s", c->user, t->name);
  byte *name = stk_printf("%s/%s", dir, filename);
}
