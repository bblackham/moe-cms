/*
 *	Sherlock Library -- Linear Representation of Objects
 *
 *	(c) 2005 Martin Mares <mj@ucw.cz>
 *	(c) 2005 Robert Spalek <robert@ucw.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

#include "sherlock/sherlock.h"
#include "lib/fastbuf.h"
#include "lib/unaligned.h"
#include "lib/lizard.h"
#include "sherlock/object.h"
#include "sherlock/lizard-fb.h"

byte *
obj_linearize(struct odes *d, uns min_compress, uns *plen)
{
  // Create uncompressed linearization
  put_attr_set_type(BUCKET_TYPE_V33);
  uns size = size_object(d);
  byte *out = xmalloc(size+LIZARD_COMPRESS_HEADER + LIZARD_NEEDS_CHARS) + LIZARD_COMPRESS_HEADER;
  byte *t = put_object(out, d);
  ASSERT(t == out+size);

  struct lizard_block_req req = {
    .type = BUCKET_TYPE_V33_LIZARD,
    .ratio = min_compress / 100.,
    .in_ptr = out,
    .in_len = size,
    .out_ptr = NULL,
    .out_len = 0,
  };
  // Allocate a buffer for compressed data
  int res = lizard_compress_req(&req);
  ASSERT(res <= 0);
  byte *buf = res<0 ? req.out_ptr=xmalloc(req.out_len+=LIZARD_COMPRESS_HEADER) : NULL;
  res = lizard_compress_req_header(&req, 1);
  ASSERT(res > 0);
  if (req.out_ptr != out-LIZARD_COMPRESS_HEADER)
    xfree(out-LIZARD_COMPRESS_HEADER);
  else if (buf)
    xfree(buf);

  *plen = req.out_len;
  return req.out_ptr;
}

struct odes *
obj_delinearize(struct buck2obj_buf *bbuf, struct mempool *mp, byte *buf, uns len, uns destructive)
{
  struct odes *o = obj_new(mp);
  ASSERT(len >= LIZARD_COMPRESS_HEADER);
  uns buck_type = buf[0] + BUCKET_TYPE_PLAIN;

  struct fastbuf fb;
  uns sh = LIZARD_COMPRESS_HEADER - 1;
  fbbuf_init_read(&fb, buf+sh, len-sh, destructive);
  if (buck2obj_parse(bbuf, buck_type, len-sh, &fb, NULL, NULL, o, 1) < 0)
    return NULL;
  else
    return o;
}
