/*
 *  The Submit Daemon: Tasks
 *
 *  (c) 2007 Martin Mares <mj@ucw.cz>
 */

#include "lib/lib.h"
#include "lib/conf.h"
#include "lib/fastbuf.h"
#include "lib/stkstring.h"
#include "lib/simple-lists.h"
#include "lib/mempool.h"
#include "sherlock/object.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "submitd.h"

clist task_list;
static clist extensions;
static clist open_data_extensions;

static byte *
tasks_conf_commit(void *p UNUSED)
{
  // We do not do any journaling here as we do not switch config files on the fly
  CLIST_FOR_EACH(struct task *, t, task_list)
    {
      clist_init(&t->parts);
      if (t->open_data)
	{
	  for (uns i=1; i<=t->open_data; i++)
	    simp_append(cf_pool, &t->parts)->s = mp_printf(cf_pool, "%d", i);
	  t->extensions = &open_data_extensions;
	}
      else
	{
	  simp_append(cf_pool, &t->parts)->s = t->name;
	  t->extensions = &extensions;
	}
    }
  return NULL;
}

static struct cf_section task_conf = {
  CF_TYPE(struct task),
  CF_ITEMS {
    CF_STRING("Name", PTR_TO(struct task, name)),
    CF_UNS("OpenData", PTR_TO(struct task, open_data)),
    CF_END
  }
};

struct cf_section tasks_conf = {
  CF_COMMIT(tasks_conf_commit),
  CF_ITEMS {
    CF_LIST("Task", &task_list, &task_conf),
    CF_LIST("Extension", &extensions, &cf_string_list_config),
    CF_LIST("OpenDataExt", &open_data_extensions, &cf_string_list_config),
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
part_exists_p(struct task *t, byte *name)
{
  CLIST_FOR_EACH(simp_node *, p, t->parts)
    if (!strcmp(p->s, name))
      return 1;
  return 0;
}

int
ext_exists_p(struct task *t, byte *ext)
{
  CLIST_FOR_EACH(simp_node *, x, *t->extensions)
    if (!strcmp(x->s, ext))
      return 1;
  return 0;
}

int
user_exists_p(byte *user)
{
  byte *fn = stk_printf("solutions/%s", user);
  struct stat st;
  return !stat(fn, &st) && S_ISDIR(st.st_mode);
}

void
task_load_status(struct conn *c)
{
  struct fastbuf *fb = bopen_try(stk_printf("solutions/%s/status", c->user), O_RDONLY, 4096);
  c->task_status = obj_new(c->pool);
  if (fb)
    {
      obj_read(fb, c->task_status);
      bclose(fb);
    }
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
  task_load_status(c);
}

void
task_unlock_status(struct conn *c, uns write_back)
{
  ASSERT(c->task_lock_fd);

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
}

struct odes *
task_status_find_task(struct conn *c, struct task *t, uns create)
{
  for (struct oattr *a = obj_find_attr(c->task_status, 'T' + OBJ_ATTR_SON); a; a=a->same)
    {
      struct odes *o = a->son;
      byte *name = obj_find_aval(o, 'T');
      ASSERT(name);
      if (!strcmp(name, t->name))
	return o;
    }
  if (!create)
    return NULL;
  struct odes *o = obj_add_son(c->task_status, 'T' + OBJ_ATTR_SON);
  obj_set_attr(o, 'T', t->name);
  return o;
}

struct odes *
task_status_find_part(struct odes *to, byte *part, uns create)
{
  for (struct oattr *a = obj_find_attr(to, 'P' + OBJ_ATTR_SON); a; a=a->same)
    {
      struct odes *o = a->son;
      byte *name = obj_find_aval(o, 'P');
      ASSERT(name);
      if (!strcmp(name, part))
	return o;
    }
  if (!create)
    return NULL;
  struct odes *o = obj_add_son(to, 'P' + OBJ_ATTR_SON);
  obj_set_attr(o, 'P', part);
  return o;
}

void task_submit_part(byte *user, byte *task, byte *part, byte *ext, uns version UNUSED, struct fastbuf *fb)
{
  byte *dir = stk_printf("solutions/%s/%s", user, task);
  byte *name = stk_printf("%s/%s.%s", dir, part, ext);

  struct stat st;
  if (stat(dir, &st) < 0 && errno == ENOENT && mkdir(dir, 0777) < 0)
    die("Cannot create %s: %m", dir);

  bconfig(fb, BCONFIG_IS_TEMP_FILE, 0);
  if (rename(fb->name, name) < 0)
    die("Cannot rename %s to %s: %m", fb->name, name);
}

void task_delete_part(byte *user, byte *task, byte *part, byte *ext, uns version UNUSED)
{
  byte *dir = stk_printf("solutions/%s/%s", user, task);
  byte *name = stk_printf("%s/%s.%s", dir, part, ext);
  if (unlink(name) < 0)
    log(L_ERROR, "Cannot delete %s: %m", name);
}
