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
};

extern clist task_list;
extern struct cf_section tasks_conf;

struct task *task_find(byte *name);
int user_exists_p(byte *user);

#endif
