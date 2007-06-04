/*
 *  The Submit Daemon
 *
 *  (c) 2007 Martin Mares <mj@ucw.cz>
 */

#ifndef _SUBMITD_H
#define _SUBMITD_H

#include "lib/clists.h"
#include "lib/ipaccess.h"
#include "lib/fastbuf.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

struct access_rule {
  cnode n;
  struct ip_addrmask addrmask;
  uns allow_admin;
  uns plain_text;
  uns max_conn;
};

struct conn {
  // Set up by the master process
  cnode n;
  u32 ip;
  byte *ip_string;			// (xmalloced)
  pid_t pid;
  uns id;
  struct access_rule *rule;		// Rule matched by this connection
  int sk;				// Client socket
  byte *cert_name;			// Client name from the certificate (NULL if no TLS) (xmalloced)

  // Used by the child process
  gnutls_session_t tls;			// TLS session
  struct fastbuf rx_fb, tx_fb;		// Fastbufs for communication with the client (either plain-text or TLS)
  struct mempool *pool;
  struct odes *request;
  struct odes *reply;
  struct odes *task_status;
  int task_lock_fd;
  byte *user;
};

extern uns max_request_size, max_attachment_size, trace_commands;

/* submitd.c */

void NONRET client_error(char *msg, ...);

/* commands.c */

int process_init(struct conn *c);
int process_command(struct conn *c);

/* tasks.c */

struct task {
  cnode n;
  byte *name;
  uns open_data;	// Number of parts for open-data tasks
  clist parts;		// List of parts of this task (simp_nodes)
  clist *extensions;	// List of allowed extensions for this task (simp_nodes)
};

extern clist task_list;
extern struct cf_section tasks_conf;

struct task *task_find(byte *name);
int part_exists_p(struct task *t, byte *name);
int user_exists_p(byte *user);
int ext_exists_p(struct task *t, byte *ext);

void task_lock_status(struct conn *c);
void task_unlock_status(struct conn *c, uns write_back);
void task_load_status(struct conn *c);

struct odes *task_status_find_task(struct conn *c, struct task *t, uns create);
struct odes *task_status_find_part(struct odes *t, byte *part, uns create);

void task_submit_part(byte *user, byte *task, byte *part, byte *ext, uns version, struct fastbuf *fb);
void task_delete_part(byte *user, byte *task, byte *part, byte *ext, uns version);

#endif
