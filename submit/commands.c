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
  put_attr_set_type(BUCKET_TYPE_PLAIN);
  bput_object(&c->tx_fb, c->reply);
  bputc(&c->tx_fb, '\n');
  bflush(&c->tx_fb);
}

static void
err(struct conn *c, byte *msg)
{
  obj_set_attr(c->reply, '-', msg);
}

/*** SUBMIT ***/

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
