#include "lib/lib.h"

#include <gnutls/gnutls.h>

static gnutls_certificate_credentials_t cert_cred;

int main(void)
{
  int err;

  gnutls_global_init();
  err = gnutls_certificate_allocate_credentials(&cert_cred);
  if (err)
    die("Unable to allocate credentials: %s", gnutls_strerror(err));
  err = gnutls_certificate_set_x509_trust_file(cert_cred, "ca-cert.pem", GNUTLS_X509_FMT_PEM);
  if (!err)
    die("No CA certificate found");
  if (err < 0)
    die("Unable to load X509 trust file: %s", gnutls_strerror(err));
  err = gnutls_certificate_set_x509_key_file(cert_cred, "server-cert.pem", "server-key.pem", GNUTLS_X509_FMT_PEM);
  if (err < 0)
    die("Unable to load X509 key file: %s", gnutls_strerror(err));

  gnutls_global_deinit();
  return 0;
}
