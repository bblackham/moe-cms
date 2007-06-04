/*
 *  The Submit Daemon: High-Level Part of the Protocol
 *
 *  (c) 2007 Martin Mares <mj@ucw.cz>
 */

#include "lib/lib.h"
#include "lib/mempool.h"
#include "sherlock/object.h"
#include "sherlock/objread.h"

#include "submitd.h"

/*** REQUESTS AND REPLIES ***/

static void NONRET
read_error_cb(struct obj_read_state *st UNUSED, byte *msg)
{
  client_error("Request parse error: %s", msg);
}

static int
read_request(struct conn *c)
{
  if (c->pool)
    mp_flush(c->pool);
  else
    c->pool = mp_new(1024);
  c->request = obj_new(c->pool);
  c->reply = obj_new(c->pool);

  struct obj_read_state st;
  obj_read_start(&st, c->request);
  st.error_callback = read_error_cb;
  byte line[1024];
  uns size = 0;
  for (;;)
    {
      int l = bgets_nodie(&c->rx_fb, line, sizeof(line));
      if (l < 0)
	client_error("Request line too long");
      if (!l)
	{
	  if (!size)
	    return 0;
	  else
	    client_error("Truncated request");
	}
      if (l == 1)
	break;
      size += l;
      if (size >= max_request_size)
	client_error("Request too long");
      obj_read_attr(&st, line[0], line+1);
    }
  obj_read_end(&st);
  return 1;
}

static void
write_reply(struct conn *c)
{
  if (!obj_find_attr(c->reply, '-') && !obj_find_attr(c->reply, '+'))
    obj_set_attr(c->reply, '+', "OK");
  if (trace_commands)
    {
      byte *msg;
      if (msg = obj_find_aval(c->reply, '-'))
	log(L_DEBUG, ">> -%s", msg);
      else if (msg = obj_find_aval(c->reply, '+'))
	log(L_DEBUG, ">> +%s", msg);
      else
	log(L_DEBUG, ">> ???");
    }
  obj_write(&c->tx_fb, c->reply, BUCKET_TYPE_PLAIN);
  bputc(&c->tx_fb, '\n');
  bflush(&c->tx_fb);
}

static void
err(struct conn *c, byte *msg)
{
  obj_set_attr(c->reply, '-', msg);
}

/*** SUBMIT ***/

static struct fastbuf *
read_attachment(struct conn *c)
{
  uns size = obj_find_anum(c->request, 'S', 0);
  if (size > max_attachment_size)
    {
      err(c, "Submission too large");
      return NULL;
    }
  obj_set_attr(c->reply, '+', "Go on");
  write_reply(c);
  obj_set_attr(c->reply, '+', NULL);

  // This is less efficient than bbcopy(), but we want our own error handling.
  struct fastbuf *fb = bopen_tmp(4096);
  byte buf[4096];
  uns remains = size;
  while (remains)
    {
      uns cnt = bread(&c->rx_fb, buf, MIN(remains, (uns)sizeof(buf)));
      if (!cnt)
	{
	  bclose(fb);
	  client_error("Truncated attachment");
	}
      bwrite(fb, buf, cnt);
      remains -= cnt;
    }
  brewind(fb);
  return fb;
}

static void
cmd_submit(struct conn *c)
{
  byte *tname = obj_find_aval(c->request, 'T');
  if (!tname)
    {
      err(c, "No task specified");
      return;
    }
  struct task *task = task_find(tname);
  if (!task)
    {
      err(c, "No such task");
      return;
    }
  struct fastbuf *fb = read_attachment(c);
  if (!fb)
    return;

  // FIXME: Check contest time
  // FIXME: Keep history of submitted tasks
  // FIXME: File names

  task_lock_status(c);
  struct odes *o = task_status_find_task(c, task);
  task_submit(c, task, fb, task->name);
  log(L_INFO, "User %s submitted task %s", c->user, task->name);
  task_unlock_status(c, 1);
}

/*** COMMAND MUX ***/

static void
execute_command(struct conn *c)
{
  byte *cmd = obj_find_aval(c->request, '!');
  if (!cmd)
    {
      err(c, "Missing command");
      return;
    }
  if (trace_commands)
    log(L_DEBUG, "<< %s", cmd);
  if (!strcasecmp(cmd, "SUBMIT"))
    cmd_submit(c);
  else
    err(c, "Unknown command");
}

int
process_command(struct conn *c)
{
  if (!read_request(c))
    return 0;
  execute_command(c);
  write_reply(c);
  return 1;
}

/*** INITIAL HANDSHAKE ***/

static void
execute_init(struct conn *c)
{
  byte *user = obj_find_aval(c->request, 'U');
  if (!user)
    {
      err(c, "Missing user");
      return;
    }
  if (!c->cert_name ||
      !strcmp(user, c->cert_name) ||
      c->rule->allow_admin && !strcmp(c->cert_name, "admin"))
    {
      if (!user_exists_p(user))
	{
	  err(c, "Unknown user");
	  return;
	}
      log(L_INFO, "Logged in %s", user);
    }
  else
    {
      err(c, "Permission denied");
      log(L_ERROR, "Unauthorized attempt to log in as %s", user);
      return;
    }
  c->user = xstrdup(user);
}

int
process_init(struct conn *c)
{
  if (!read_request(c))
    return 0;
  execute_init(c);
  write_reply(c);
  return !obj_find_attr(c->reply, '-');
}
