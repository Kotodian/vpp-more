/*
 * ovpn.c - ovpn source file
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ovpn/ovpn.h>
#include <ovpn/ovpn_if.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_handshake.h>
#include <ovpn/ovpn_mgmt.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vppinfra/error.h>
#include <vnet/ip/format.h>
#include <vnet/fib/fib_types.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_table.h>
#include <vppinfra/unix.h>
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp.h>
#include <vnet/ip/ip.h>
#include <stddef.h>
#include <vpp/app/version.h>
#include <picotls/openssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>

ovpn_main_t ovpn_main;

/* External node declarations */
extern vlib_node_registration_t ovpn4_input_node;
extern vlib_node_registration_t ovpn6_input_node;
extern vlib_node_registration_t ovpn4_output_node;
extern vlib_node_registration_t ovpn6_output_node;

/* Picotls key exchange algorithms */
static ptls_key_exchange_algorithm_t *ovpn_key_exchange[] = {
#ifdef PTLS_OPENSSL_HAVE_X25519
  &ptls_openssl_x25519,
#endif
#ifdef PTLS_OPENSSL_HAVE_SECP256R1
  &ptls_openssl_secp256r1,
#endif
#ifdef PTLS_OPENSSL_HAVE_SECP384R1
  &ptls_openssl_secp384r1,
#endif
#ifdef PTLS_OPENSSL_HAVE_SECP521R1
  &ptls_openssl_secp521r1,
#endif
  NULL
};

/* Picotls cipher suites */
static ptls_cipher_suite_t *ovpn_cipher_suites[] = {
  &ptls_openssl_aes128gcmsha256, &ptls_openssl_aes256gcmsha384,
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
  &ptls_openssl_chacha20poly1305sha256,
#endif
  NULL
};

/* Signature algorithms for client certificate verification
 * Must be terminated by UINT16_MAX */
static const uint16_t ovpn_signature_algorithms[] = {
  PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
  PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
  PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512,
  PTLS_SIGNATURE_RSA_PKCS1_SHA256,
  PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
  PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
  PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512,
  UINT16_MAX
};

static clib_error_t *
ovpn_read_file_contents (char *file_path, u8 **result)
{
  clib_error_t *error;

  if (!file_path)
    return clib_error_return (0, "file path is NULL");

  error = clib_file_contents (file_path, result);
  if (error)
    return clib_error_return (0, "failed to read file '%s': %U", file_path,
			      format_clib_error, error);

  return 0;
}

static int
ovpn_load_certificates (ptls_context_t *ctx, u8 *cert_data, u8 *key_data)
{
  BIO *key_bio = NULL;
  BIO *cert_bio = NULL;
  EVP_PKEY *pkey = NULL;
  X509 *x509 = NULL;
  ptls_openssl_sign_certificate_t *sign_cert = NULL;
  u8 *der_cert = NULL;
  int der_len = 0;
  int ret = -1;

  if (!cert_data || !key_data)
    return -1;

  /* Load private key */
  key_bio = BIO_new_mem_buf (key_data, vec_len (key_data));
  if (!key_bio)
    goto done;

  pkey = PEM_read_bio_PrivateKey (key_bio, NULL, NULL, NULL);
  if (!pkey)
    goto done;

  /* Load certificate from PEM and convert to DER */
  cert_bio = BIO_new_mem_buf (cert_data, vec_len (cert_data));
  if (!cert_bio)
    goto done;

  x509 = PEM_read_bio_X509 (cert_bio, NULL, NULL, NULL);
  if (!x509)
    goto done;

  /* Get DER encoding length */
  der_len = i2d_X509 (x509, NULL);
  if (der_len <= 0)
    goto done;

  /* Allocate and convert to DER */
  der_cert = clib_mem_alloc (der_len);
  if (!der_cert)
    goto done;

  {
    u8 *der_ptr = der_cert;
    if (i2d_X509 (x509, &der_ptr) != der_len)
      goto done;
  }

  /* Allocate and setup sign certificate */
  sign_cert =
    (ptls_openssl_sign_certificate_t *) clib_mem_alloc (sizeof (*sign_cert));
  if (!sign_cert)
    goto done;

  clib_memset (sign_cert, 0, sizeof (*sign_cert));

  if (ptls_openssl_init_sign_certificate (sign_cert, pkey) != 0)
    {
      clib_mem_free (sign_cert);
      sign_cert = NULL;
      /* pkey was not transferred to sign_cert, so we must free it */
      EVP_PKEY_free (pkey);
      pkey = NULL;
      goto done;
    }

  ctx->sign_certificate = &sign_cert->super;

  /* Setup certificates - use DER-encoded certificate */
  ptls_iovec_t *certs = clib_mem_alloc (2 * sizeof (ptls_iovec_t));
  if (!certs)
    {
      /* ptls_openssl_init_sign_certificate succeeded, so pkey may have been
       * transferred to sign_cert. We clear ctx->sign_certificate and free
       * sign_cert. The done label will check ctx->sign_certificate to
       * determine if pkey needs freeing. */
      ctx->sign_certificate = NULL;
      clib_mem_free (sign_cert);
      sign_cert = NULL;
      goto done;
    }
  certs[0].base = der_cert;
  certs[0].len = der_len;
  certs[1].base = NULL;
  certs[1].len = 0;
  der_cert = NULL; /* Transfer ownership to ctx */

  ctx->certificates.list = certs;
  ctx->certificates.count = 1;

  ret = 0;

done:
  if (key_bio)
    BIO_free (key_bio);
  if (cert_bio)
    BIO_free (cert_bio);
  if (x509)
    X509_free (x509);
  if (der_cert)
    clib_mem_free (der_cert);
  /* Note: pkey is only owned by sign_cert if
   * ptls_openssl_init_sign_certificate succeeded AND ctx->sign_certificate is
   * still set. We check ctx->sign_certificate to determine if pkey was
   * transferred. If ctx->sign_certificate is NULL, pkey was not transferred
   * (or sign_cert was freed) and must be freed. */
  if (pkey && !ctx->sign_certificate)
    EVP_PKEY_free (pkey);

  return ret;
}

static void
ovpn_free_options (ovpn_options_t *opt)
{
  vec_free (opt->dev_name);
  vec_free (opt->ca_cert);
  vec_free (opt->server_cert);
  vec_free (opt->server_key);
  vec_free (opt->dh_params);
  vec_free (opt->tls_crypt_key);
  vec_free (opt->tls_crypt_v2_key);
  vec_free (opt->tls_auth_key);
  vec_free (opt->cipher_name);
  vec_free (opt->auth_name);
  clib_memset (opt, 0, sizeof (*opt));
  opt->sw_if_index = ~0;
}

/*
 * Custom certificate verification structure for CN extraction and chain
 * verification. This extends ptls_verify_certificate_t to store CA store
 * and extracted CN.
 */
typedef struct ovpn_verify_certificate_t_
{
  ptls_verify_certificate_t super;
  ovpn_instance_t *inst;    /* Back pointer to instance */
  X509_STORE *ca_store;	    /* CA certificate store for chain verification */
  u8 verify_client_cert;    /* Whether to verify client certificates */
  u8 crl_enabled;	    /* Whether CRL checking is enabled */
} ovpn_verify_certificate_t;

/*
 * Extract Common Name (CN) from X.509 certificate subject
 * Returns allocated string that caller must free, or NULL on error
 */
static char *
ovpn_extract_cn_from_cert (const u8 *cert_der, size_t cert_len)
{
  X509 *x509 = NULL;
  X509_NAME *subject = NULL;
  char *cn = NULL;
  int cn_len;

  /* Parse DER-encoded certificate */
  const u8 *p = cert_der;
  x509 = d2i_X509 (NULL, &p, cert_len);
  if (!x509)
    {
      clib_warning ("ovpn: failed to parse client certificate");
      return NULL;
    }

  /* Get subject name */
  subject = X509_get_subject_name (x509);
  if (!subject)
    {
      clib_warning ("ovpn: failed to get certificate subject");
      X509_free (x509);
      return NULL;
    }

  /* Find CN in subject */
  cn_len = X509_NAME_get_text_by_NID (subject, NID_commonName, NULL, 0);
  if (cn_len <= 0)
    {
      clib_warning ("ovpn: no CN found in certificate subject");
      X509_free (x509);
      return NULL;
    }

  /* Allocate and extract CN (+1 for null terminator) */
  cn = clib_mem_alloc (cn_len + 1);
  if (!cn)
    {
      X509_free (x509);
      return NULL;
    }

  if (X509_NAME_get_text_by_NID (subject, NID_commonName, cn, cn_len + 1) <= 0)
    {
      clib_mem_free (cn);
      cn = NULL;
    }

  X509_free (x509);
  return cn;
}

/*
 * Extract full subject DN from X.509 certificate
 * Returns allocated string that caller must free, or NULL on error
 */
static char *
ovpn_extract_subject_from_cert (const u8 *cert_der, size_t cert_len)
{
  X509 *x509 = NULL;
  X509_NAME *subject = NULL;
  char *subject_str = NULL;
  BIO *bio = NULL;
  BUF_MEM *bptr;

  /* Parse DER-encoded certificate */
  const u8 *p = cert_der;
  x509 = d2i_X509 (NULL, &p, cert_len);
  if (!x509)
    return NULL;

  /* Get subject name */
  subject = X509_get_subject_name (x509);
  if (!subject)
    {
      X509_free (x509);
      return NULL;
    }

  /* Convert subject to string using OpenSSL one-line format */
  bio = BIO_new (BIO_s_mem ());
  if (!bio)
    {
      X509_free (x509);
      return NULL;
    }

  X509_NAME_print_ex (bio, subject, 0, XN_FLAG_ONELINE);
  BIO_get_mem_ptr (bio, &bptr);

  subject_str = clib_mem_alloc (bptr->length + 1);
  if (subject_str)
    {
      clib_memcpy (subject_str, bptr->data, bptr->length);
      subject_str[bptr->length] = 0;
    }

  BIO_free (bio);
  X509_free (x509);
  return subject_str;
}

/*
 * Verify certificate chain using CA store
 * Returns 0 on success, negative error code on failure
 */
static int
ovpn_verify_cert_chain (X509_STORE *ca_store, ptls_iovec_t *certs,
			size_t num_certs)
{
  X509_STORE_CTX *store_ctx = NULL;
  STACK_OF (X509) *chain = NULL;
  X509 *leaf_cert = NULL;
  const u8 *p;
  int ret = -1;
  int verify_result;

  if (!ca_store || num_certs == 0)
    return -1;

  /* Parse the leaf certificate (first in chain) */
  p = certs[0].base;
  leaf_cert = d2i_X509 (NULL, &p, certs[0].len);
  if (!leaf_cert)
    {
      clib_warning ("ovpn: failed to parse leaf certificate");
      return -1;
    }

  /* Build intermediate certificate chain if provided */
  chain = sk_X509_new_null ();
  if (!chain)
    {
      X509_free (leaf_cert);
      return -1;
    }

  for (size_t i = 1; i < num_certs; i++)
    {
      X509 *intermediate;
      p = certs[i].base;
      intermediate = d2i_X509 (NULL, &p, certs[i].len);
      if (intermediate)
	{
	  sk_X509_push (chain, intermediate);
	}
    }

  /* Create verification context */
  store_ctx = X509_STORE_CTX_new ();
  if (!store_ctx)
    {
      sk_X509_pop_free (chain, X509_free);
      X509_free (leaf_cert);
      return -1;
    }

  /* Initialize verification context */
  if (X509_STORE_CTX_init (store_ctx, ca_store, leaf_cert, chain) != 1)
    {
      clib_warning ("ovpn: failed to init X509_STORE_CTX");
      goto cleanup;
    }

  /* Set verification flags - allow partial chain if intermediate is trusted */
  X509_STORE_CTX_set_flags (store_ctx, X509_V_FLAG_PARTIAL_CHAIN);

  /* Perform the verification */
  verify_result = X509_verify_cert (store_ctx);
  if (verify_result != 1)
    {
      int err = X509_STORE_CTX_get_error (store_ctx);
      clib_warning ("ovpn: certificate chain verification failed: %s",
		    X509_verify_cert_error_string (err));
      ret = -err;
      goto cleanup;
    }

  ret = 0; /* Success */

cleanup:
  X509_STORE_CTX_free (store_ctx);
  sk_X509_pop_free (chain, X509_free);
  X509_free (leaf_cert);
  return ret;
}

/*
 * Certificate verification callback
 * This is called during TLS handshake to verify the peer's certificate.
 * We verify the certificate chain and extract Common Name for CCD lookup.
 */
static int
ovpn_verify_certificate_cb (ptls_verify_certificate_t *self, ptls_t *tls,
			    const char *server_name,
			    int (**verify_sign) (void *, uint16_t, ptls_iovec_t,
						 ptls_iovec_t),
			    void **verify_data, ptls_iovec_t *certs,
			    size_t num_certs)
{
  ovpn_verify_certificate_t *vc = (ovpn_verify_certificate_t *) self;
  char *cn = NULL;
  int ret = 0;

  (void) server_name;

  /* We need at least one certificate (the leaf/client cert) */
  if (num_certs == 0 || certs[0].len == 0)
    {
      clib_warning ("ovpn: no client certificate provided");
      /* Allow connections without certificates only if verify is disabled */
      if (vc->verify_client_cert)
	return PTLS_ALERT_CERTIFICATE_REQUIRED;
      *verify_sign = NULL;
      *verify_data = NULL;
      return 0;
    }

  /*
   * Verify certificate chain if CA store is configured
   */
  if (vc->ca_store && vc->verify_client_cert)
    {
      ret = ovpn_verify_cert_chain (vc->ca_store, certs, num_certs);
      if (ret != 0)
	{
	  clib_warning ("ovpn: rejecting client - certificate chain "
			"verification failed");
	  return PTLS_ALERT_BAD_CERTIFICATE;
	}
    }

  /*
   * Verify certificate name if verify-x509-name is configured
   */
  if (vc->inst->options.verify_x509_name)
    {
      const char *expected = (const char *) vc->inst->options.verify_x509_name;
      char *actual = NULL;
      int match = 0;

      switch (vc->inst->options.verify_x509_type)
	{
	case OVPN_X509_VERIFY_NAME:
	  /* Exact CN match */
	  actual = ovpn_extract_cn_from_cert (certs[0].base, certs[0].len);
	  if (actual && strcmp (actual, expected) == 0)
	    match = 1;
	  break;

	case OVPN_X509_VERIFY_NAME_PREFIX:
	  /* CN prefix match */
	  actual = ovpn_extract_cn_from_cert (certs[0].base, certs[0].len);
	  if (actual && strncmp (actual, expected, strlen (expected)) == 0)
	    match = 1;
	  break;

	case OVPN_X509_VERIFY_SUBJECT:
	  /* Full subject DN match */
	  actual = ovpn_extract_subject_from_cert (certs[0].base, certs[0].len);
	  if (actual && strcmp (actual, expected) == 0)
	    match = 1;
	  break;
	}

      if (actual)
	clib_mem_free (actual);

      if (!match)
	{
	  clib_warning ("ovpn: rejecting client - verify-x509-name failed");
	  return PTLS_ALERT_BAD_CERTIFICATE;
	}
    }

  /* Extract CN from the leaf certificate (certs[0]) */
  cn = ovpn_extract_cn_from_cert (certs[0].base, certs[0].len);
  if (cn)
    {
      /*
       * Store CN in the ptls user data pointer for later retrieval.
       * The peer code will retrieve this after handshake completes.
       */
      void **data_ptr = ptls_get_data_ptr (tls);
      if (data_ptr)
	{
	  /* Free any existing CN */
	  if (*data_ptr)
	    clib_mem_free (*data_ptr);
	  *data_ptr = cn;
	}
      else
	{
	  clib_mem_free (cn);
	}
    }

  *verify_sign = NULL;
  *verify_data = NULL;

  return 0; /* Accept certificate */
}

/*
 * Load CA certificate(s) into X509_STORE for chain verification
 * Supports both PEM and DER formats, and CA files containing multiple certs
 * Returns X509_STORE on success, NULL on failure
 */
static X509_STORE *
ovpn_load_ca_store (const u8 *ca_data, u32 ca_len)
{
  X509_STORE *store = NULL;
  BIO *bio = NULL;
  X509 *cert = NULL;
  int cert_count = 0;

  if (!ca_data || ca_len == 0)
    return NULL;

  store = X509_STORE_new ();
  if (!store)
    return NULL;

  /* Create BIO from the CA data */
  bio = BIO_new_mem_buf (ca_data, ca_len);
  if (!bio)
    {
      X509_STORE_free (store);
      return NULL;
    }

  /* Try to load as PEM first (may contain multiple certificates) */
  while ((cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL)) != NULL)
    {
      if (X509_STORE_add_cert (store, cert) != 1)
	{
	  clib_warning ("ovpn: failed to add CA cert to store");
	}
      else
	{
	  cert_count++;
	}
      X509_free (cert);
    }

  /* Clear any error from the PEM loop reaching end of file */
  ERR_clear_error ();

  /* If no PEM certs found, try DER format */
  if (cert_count == 0)
    {
      BIO_reset (bio);
      cert = d2i_X509_bio (bio, NULL);
      if (cert)
	{
	  if (X509_STORE_add_cert (store, cert) == 1)
	    cert_count++;
	  X509_free (cert);
	}
    }

  BIO_free (bio);

  if (cert_count == 0)
    {
      clib_warning ("ovpn: no valid CA certificates found");
      X509_STORE_free (store);
      return NULL;
    }

  return store;
}

/*
 * Load CRL file and add to X509_STORE
 * Supports both PEM and DER formats
 * Returns 0 on success, <0 on error
 */
static int
ovpn_load_crl (X509_STORE *store, const u8 *crl_data, u32 crl_len)
{
  BIO *bio = NULL;
  X509_CRL *crl = NULL;
  int crl_count = 0;

  if (!store || !crl_data || crl_len == 0)
    return -1;

  /* Create BIO from CRL data */
  bio = BIO_new_mem_buf (crl_data, crl_len);
  if (!bio)
    return -1;

  /* Try to load as PEM first (may contain multiple CRLs) */
  while ((crl = PEM_read_bio_X509_CRL (bio, NULL, NULL, NULL)) != NULL)
    {
      if (X509_STORE_add_crl (store, crl) != 1)
	{
	  clib_warning ("ovpn: failed to add CRL to store");
	}
      else
	{
	  crl_count++;
	}
      X509_CRL_free (crl);
    }

  /* Clear any error from the PEM loop reaching end of file */
  ERR_clear_error ();

  /* If no PEM CRLs found, try DER format */
  if (crl_count == 0)
    {
      BIO_reset (bio);
      crl = d2i_X509_CRL_bio (bio, NULL);
      if (crl)
	{
	  if (X509_STORE_add_crl (store, crl) == 1)
	    crl_count++;
	  X509_CRL_free (crl);
	}
    }

  BIO_free (bio);

  if (crl_count == 0)
    {
      clib_warning ("ovpn: no valid CRLs found in file");
      return -1;
    }

  /* Enable CRL checking flags on the store */
  X509_STORE_set_flags (store, X509_V_FLAG_CRL_CHECK |
				 X509_V_FLAG_CRL_CHECK_ALL);

  return 0;
}

static clib_error_t *
ovpn_init_picotls_context_for_instance (ovpn_instance_t *inst)
{
  ptls_context_t *ctx;
  ovpn_verify_certificate_t *verify_cert;

  /* Allocate and initialize picotls context */
  ctx = clib_mem_alloc (sizeof (ptls_context_t));
  if (!ctx)
    return clib_error_return (0, "failed to allocate picotls context");

  clib_memset (ctx, 0, sizeof (ptls_context_t));

  /* Setup basic context */
  ctx->random_bytes = ptls_openssl_random_bytes;
  ctx->key_exchanges = ovpn_key_exchange;
  ctx->cipher_suites = ovpn_cipher_suites;
  ctx->get_time = &ptls_get_time;
  ctx->require_dhe_on_psk = 1;
  ctx->max_early_data_size = 0;
  ctx->use_exporter = 1; /* Enable TLS-EKM (RFC 5705) for OpenVPN key derivation */

  /* Request client certificate for CN extraction and authentication */
  ctx->require_client_authentication = 1;

  /* Setup certificate verification callback for CN extraction and chain
   * verification */
  verify_cert = clib_mem_alloc (sizeof (ovpn_verify_certificate_t));
  if (!verify_cert)
    {
      clib_mem_free (ctx);
      return clib_error_return (0, "failed to allocate verify context");
    }
  clib_memset (verify_cert, 0, sizeof (*verify_cert));
  verify_cert->super.cb = ovpn_verify_certificate_cb;
  verify_cert->super.algos = ovpn_signature_algorithms;
  verify_cert->inst = inst;

  /* Load CA certificate store for chain verification if CA cert provided */
  if (inst->options.ca_cert && vec_len (inst->options.ca_cert) > 0)
    {
      verify_cert->ca_store =
	ovpn_load_ca_store (inst->options.ca_cert, vec_len (inst->options.ca_cert));
      if (verify_cert->ca_store)
	{
	  verify_cert->verify_client_cert = 1;
	  clib_warning ("ovpn: certificate chain verification enabled");

	  /* Load CRL if configured */
	  if (inst->options.crl_file && vec_len (inst->options.crl_file) > 0)
	    {
	      if (ovpn_load_crl (verify_cert->ca_store, inst->options.crl_file,
				vec_len (inst->options.crl_file)) == 0)
		{
		  verify_cert->crl_enabled = 1;
		}
	      else
		{
		  clib_warning ("ovpn: CRL loading failed, continuing without "
				"CRL checking");
		}
	    }
	}
      else
	{
	  clib_warning ("ovpn: failed to load CA, chain verification disabled");
	}
    }

  ctx->verify_certificate = &verify_cert->super;

  /* Load certificates if provided */
  if (inst->options.server_cert && inst->options.server_key)
    {
      if (ovpn_load_certificates (ctx, inst->options.server_cert,
				  inst->options.server_key) != 0)
	{
	  if (verify_cert->ca_store)
	    X509_STORE_free (verify_cert->ca_store);
	  clib_mem_free (verify_cert);
	  clib_mem_free (ctx);
	  return clib_error_return (0, "failed to load certificates");
	}
    }

  inst->ptls_ctx = ctx;
  return 0;
}

static void
ovpn_cleanup_picotls_context_for_instance (ovpn_instance_t *inst)
{
  ptls_openssl_sign_certificate_t *sign_cert;

  if (!inst->ptls_ctx)
    return;

  /* Free verify_certificate structure and its resources */
  if (inst->ptls_ctx->verify_certificate)
    {
      ovpn_verify_certificate_t *vc =
	(ovpn_verify_certificate_t *) inst->ptls_ctx->verify_certificate;

      /* Free the CA store if it was allocated */
      if (vc->ca_store)
	X509_STORE_free (vc->ca_store);

      clib_mem_free (vc);
    }

  /* Free sign_certificate structure if it exists */
  if (inst->ptls_ctx->sign_certificate)
    {
      /* ctx->sign_certificate points to sign_cert->super, so we need to
       * get the containing structure */
      sign_cert = (ptls_openssl_sign_certificate_t
		     *) ((char *) inst->ptls_ctx->sign_certificate -
			 offsetof (ptls_openssl_sign_certificate_t, super));
      clib_mem_free (sign_cert);
    }

  if (inst->ptls_ctx->certificates.list)
    clib_mem_free ((void *) inst->ptls_ctx->certificates.list);

  clib_mem_free (inst->ptls_ctx);
  inst->ptls_ctx = NULL;
}

/*
 * Instance management functions
 */

int
ovpn_instance_create (vlib_main_t *vm, ip_address_t *local_addr,
		      u16 local_port, u32 table_id, ovpn_options_t *options,
		      u32 *instance_id_out, u32 *sw_if_index_out)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_instance_t *inst;
  clib_error_t *error = NULL;
  u32 sw_if_index = ~0;
  int rv;

  /* Check if port is already in use */
  if (vec_len (omp->instance_id_by_port) > local_port &&
      omp->instance_id_by_port[local_port] != ~0)
    {
      return VNET_API_ERROR_VALUE_EXIST;
    }

  /* Allocate instance from pool */
  pool_get_zero (omp->instances, inst);
  inst->instance_id = inst - omp->instances;

  /* Copy local address and port */
  clib_memcpy (&inst->local_addr, local_addr, sizeof (ip_address_t));
  inst->local_port = local_port;
  inst->is_ipv6 = (ip_addr_version (local_addr) == AF_IP6);

  /* Setup per-instance FIB tables */
  inst->fib_table_id = table_id;
  inst->fib_index4 = fib_table_find_or_create_and_lock (
    FIB_PROTOCOL_IP4, table_id, omp->fib_src_hi);
  inst->fib_index6 = fib_table_find_or_create_and_lock (
    FIB_PROTOCOL_IP6, table_id, omp->fib_src_hi);

  /* Copy options to instance */
  clib_memcpy (&inst->options, options, sizeof (ovpn_options_t));

  /*
   * Ensure server_addr is set from local_addr.
   * This is needed for static key mode peer rewrite generation.
   */
  if (inst->options.server_addr.fp_addr.ip4.as_u32 == 0 &&
      ip6_address_is_zero (&inst->options.server_addr.fp_addr.ip6))
    {
      if (inst->is_ipv6)
	{
	  inst->options.server_addr.fp_proto = FIB_PROTOCOL_IP6;
	  inst->options.server_addr.fp_len = 128;
	  clib_memcpy (&inst->options.server_addr.fp_addr.ip6,
		       &local_addr->ip.ip6, sizeof (ip6_address_t));
	}
      else
	{
	  inst->options.server_addr.fp_proto = FIB_PROTOCOL_IP4;
	  inst->options.server_addr.fp_len = 32;
	  inst->options.server_addr.fp_addr.ip4.as_u32 =
	    local_addr->ip.ip4.as_u32;
	}
    }

  /* Generate device name if not provided */
  if (!inst->options.dev_name)
    {
      inst->options.dev_name =
	(char *) format (0, "ovpn%u%c", inst->instance_id, 0);
    }

  /* Parse TLS-Crypt key if provided */
  if (inst->options.tls_crypt_key)
    {
      rv = ovpn_tls_crypt_parse_key (inst->options.tls_crypt_key,
				     vec_len (inst->options.tls_crypt_key),
				     &inst->tls_crypt, 1);
      if (rv < 0)
	{
	  pool_put (omp->instances, inst);
	  return VNET_API_ERROR_INVALID_VALUE;
	}
    }

  /* Parse TLS-Auth key if provided */
  if (inst->options.tls_auth_key)
    {
      rv = ovpn_tls_auth_parse_key (inst->options.tls_auth_key,
				    vec_len (inst->options.tls_auth_key),
				    &inst->tls_auth, 1);
      if (rv < 0)
	{
	  pool_put (omp->instances, inst);
	  return VNET_API_ERROR_INVALID_VALUE_2;
	}
    }

  /* Parse TLS-Crypt-V2 server key if provided */
  if (inst->options.tls_crypt_v2_key)
    {
      rv = ovpn_tls_crypt_v2_parse_server_key (inst->options.tls_crypt_v2_key,
					       vec_len (inst->options.tls_crypt_v2_key),
					       &inst->tls_crypt_v2);
      if (rv < 0)
	{
	  pool_put (omp->instances, inst);
	  return VNET_API_ERROR_INVALID_VALUE_3;
	}
    }

  /* Set cipher algorithm */
  if (inst->options.cipher_name)
    {
      inst->cipher_alg =
	ovpn_crypto_cipher_alg_from_name ((char *) inst->options.cipher_name);
    }
  else if (inst->options.static_key_mode)
    {
      inst->cipher_alg = OVPN_CIPHER_ALG_AES_256_CBC;
    }
  else
    {
      inst->cipher_alg = OVPN_CIPHER_ALG_AES_256_GCM;
    }

  /* Initialize replay protection for TLS-Crypt */
  if (inst->tls_crypt.enabled && inst->options.replay_protection)
    {
      inst->tls_crypt.time_backtrack = inst->options.replay_time;
      inst->tls_crypt.replay_time_floor = 0;
    }

  /* Initialize picotls context (only for TLS mode) */
  if (!inst->options.static_key_mode)
    {
      error = ovpn_init_picotls_context_for_instance (inst);
      if (error)
	{
	  clib_error_report (error);
	  pool_put (omp->instances, inst);
	  return VNET_API_ERROR_INIT_FAILED;
	}
    }

  /* Create the OpenVPN interface */
  rv = ovpn_if_create (vm, (u8 *) inst->options.dev_name, inst->options.is_tun,
		       inst->options.mtu, &sw_if_index);
  if (rv != 0)
    {
      ovpn_cleanup_picotls_context_for_instance (inst);
      pool_put (omp->instances, inst);
      return VNET_API_ERROR_INVALID_INTERFACE;
    }

  inst->sw_if_index = sw_if_index;
  inst->options.sw_if_index = sw_if_index;

  /* Bind interface to per-instance FIB tables */
  ip_table_bind (FIB_PROTOCOL_IP4, sw_if_index, inst->fib_table_id);
  ip_table_bind (FIB_PROTOCOL_IP6, sw_if_index, inst->fib_table_id);

  /* Register UDP port for this instance */
  udp_register_dst_port (vm, local_port, ovpn4_input_node.index, UDP_IP4);
  udp_register_dst_port (vm, local_port, ovpn6_input_node.index, UDP_IP6);

  /* Initialize peer and pending databases for this instance */
  ovpn_peer_db_init (&inst->multi_context.peer_db, sw_if_index,
		     inst->options.max_clients);
  ovpn_pending_db_init (&inst->multi_context.pending_db);

  /* Load ifconfig-pool-persist file if configured */
  if (inst->options.ifconfig_pool_persist_file)
    {
      ovpn_peer_persist_load (&inst->multi_context.peer_db,
			      (char *) inst->options.ifconfig_pool_persist_file);
    }

  /* Setup port-to-instance lookup */
  vec_validate_init_empty (omp->instance_id_by_port, local_port, ~0);
  omp->instance_id_by_port[local_port] = inst->instance_id;

  /* Setup sw_if_index-to-instance lookup */
  hash_set (omp->instance_by_sw_if_index, sw_if_index, inst->instance_id);

  inst->is_active = 1;

  /*
   * Enable management interface if configured (UDP only via VPP session layer)
   */
  if (inst->options.management_enabled)
    {
      int mgmt_rv;
      /* UDP mode via VPP session layer */
      mgmt_rv = ovpn_mgmt_enable (vm, inst->instance_id,
				  &inst->options.management_ip,
				  inst->options.management_port,
				  inst->options.management_password);

      if (mgmt_rv == 0)
	{
	  /* Configure management options */
	  ovpn_mgmt_t *mgmt = ovpn_mgmt_get_by_instance (inst->instance_id);
	  if (mgmt)
	    {
	      if (inst->options.management_hold)
		ovpn_mgmt_set_hold (mgmt, 1);
	      if (inst->options.management_log_cache > 0)
		{
		  /* Resize log history buffer */
		  mgmt->log_history_size = inst->options.management_log_cache;
		  vec_free (mgmt->log_history);
		  vec_validate (mgmt->log_history, mgmt->log_history_size - 1);
		}
	    }
	}
      /* Note: management failure is not fatal to instance creation */
    }

  *instance_id_out = inst->instance_id;
  *sw_if_index_out = sw_if_index;

  return 0;
}

int
ovpn_instance_delete (vlib_main_t *vm, u32 sw_if_index)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_instance_t *inst;

  inst = ovpn_instance_get_by_sw_if_index (sw_if_index);
  if (!inst)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* Disable management interface if enabled */
  if (inst->options.management_enabled)
    ovpn_mgmt_disable (vm, inst->instance_id);

  /* Unregister UDP port */
  udp_unregister_dst_port (vm, inst->local_port, UDP_IP4);
  udp_unregister_dst_port (vm, inst->local_port, UDP_IP6);

  /* Unbind interface from FIB tables before deleting */
  ip_table_bind (FIB_PROTOCOL_IP4, sw_if_index, 0);
  ip_table_bind (FIB_PROTOCOL_IP6, sw_if_index, 0);

  /* Delete the interface */
  ovpn_if_delete (vm, sw_if_index);

  /* Cleanup databases */
  ovpn_peer_db_free (&inst->multi_context.peer_db);
  ovpn_pending_db_free (&inst->multi_context.pending_db);

  /* Cleanup picotls context */
  ovpn_cleanup_picotls_context_for_instance (inst);

  /* Free options */
  ovpn_free_options (&inst->options);

  /* Unlock FIB tables */
  fib_table_unlock (inst->fib_index4, FIB_PROTOCOL_IP4, omp->fib_src_hi);
  fib_table_unlock (inst->fib_index6, FIB_PROTOCOL_IP6, omp->fib_src_hi);

  /* Remove from lookups */
  if (vec_len (omp->instance_id_by_port) > inst->local_port)
    omp->instance_id_by_port[inst->local_port] = ~0;

  hash_unset (omp->instance_by_sw_if_index, sw_if_index);

  /* Free instance */
  pool_put (omp->instances, inst);

  return 0;
}

static clib_error_t *
ovpn_show_command_fn (vlib_main_t *vm,
		      unformat_input_t *input __attribute__ ((unused)),
		      vlib_cli_command_t *cmd __attribute__ ((unused)))
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_instance_t *inst;

  if (pool_elts (omp->instances) == 0)
    {
      vlib_cli_output (vm, "No OpenVPN instances configured");
      return 0;
    }

  vlib_cli_output (
    vm, "OpenVPN Instances (%u configured):", pool_elts (omp->instances));

  pool_foreach (inst, omp->instances)
    {
      ovpn_options_t *opt = &inst->options;

      vlib_cli_output (
	vm, "\nInstance %u (interface %s, sw_if_index %u):", inst->instance_id,
	inst->options.dev_name, inst->sw_if_index);
      vlib_cli_output (vm, "  Status: %s",
		       inst->is_active ? "Active" : "Inactive");
      vlib_cli_output (vm, "  Local: %U port %u", format_ip_address,
		       &inst->local_addr, inst->local_port);
      vlib_cli_output (vm, "  FIB table: %u (IPv4 index %u, IPv6 index %u)",
		       inst->fib_table_id, inst->fib_index4, inst->fib_index6);
      vlib_cli_output (vm, "  Mode: %s",
		       opt->static_key_mode ? "Static Key" : "TLS");
      vlib_cli_output (vm, "  Device Type: %s",
		       opt->is_tun ? "TUN (L3)" : "TAP (L2)");
      vlib_cli_output (vm, "  MTU: %u", opt->mtu);

      if (opt->static_key_mode)
	vlib_cli_output (vm, "  Static Key Direction: %u",
			 opt->static_key_direction);
      else
	vlib_cli_output (vm, "  Picotls Context: %s",
			 inst->ptls_ctx ? "Initialized" : "Not initialized");

      vlib_cli_output (
	vm, "  Cipher Algorithm: %s",
	inst->cipher_alg == OVPN_CIPHER_ALG_AES_128_GCM ? "AES-128-GCM" :
	inst->cipher_alg == OVPN_CIPHER_ALG_AES_256_GCM ? "AES-256-GCM" :
	inst->cipher_alg == OVPN_CIPHER_ALG_CHACHA20_POLY1305 ?
							  "CHACHA20-POLY1305" :
	inst->cipher_alg == OVPN_CIPHER_ALG_AES_256_CBC ? "AES-256-CBC" :
							  "NONE");

      if (inst->tls_crypt.enabled)
	vlib_cli_output (vm, "  TLS-Crypt: enabled");
      if (inst->tls_crypt_v2.enabled)
	vlib_cli_output (vm, "  TLS-Crypt-V2: enabled");
      if (inst->tls_auth.enabled)
	vlib_cli_output (vm, "  TLS-Auth: enabled");

      vlib_cli_output (vm, "  Keepalive: ping %u, timeout %u",
		       opt->keepalive_ping, opt->keepalive_timeout);
      vlib_cli_output (vm, "  Peers: %u",
		       pool_elts (inst->multi_context.peer_db.peers));

      /* Show data ciphers */
      if (opt->n_data_ciphers > 0)
	{
	  vlib_cli_output (vm, "  Data Ciphers (%u):", opt->n_data_ciphers);
	  for (u32 i = 0; i < opt->n_data_ciphers; i++)
	    vlib_cli_output (vm, "    [%u] %s", i, opt->data_ciphers[i]);
	}

      /* Show DHCP options */
      if (opt->n_dhcp_options > 0)
	{
	  vlib_cli_output (vm, "  DHCP Options (%u):", opt->n_dhcp_options);
	  for (u32 i = 0; i < opt->n_dhcp_options; i++)
	    {
	      ovpn_dhcp_option_t *dhcp = &opt->dhcp_options[i];
	      const char *type_str =
		dhcp->type == OVPN_DHCP_OPTION_DNS	   ? "DNS" :
		dhcp->type == OVPN_DHCP_OPTION_WINS	   ? "WINS" :
		dhcp->type == OVPN_DHCP_OPTION_DOMAIN	   ? "DOMAIN" :
		dhcp->type == OVPN_DHCP_OPTION_NTP	   ? "NTP" :
		dhcp->type == OVPN_DHCP_OPTION_DISABLE_NBT ? "DISABLE-NBT" :
							     "UNKNOWN";
	      if (dhcp->type == OVPN_DHCP_OPTION_DOMAIN && dhcp->string)
		vlib_cli_output (vm, "    %s: %s", type_str, dhcp->string);
	      else
		vlib_cli_output (vm, "    %s: %U", type_str, format_ip_address,
				 &dhcp->ip);
	    }
	}

      /* Show push routes */
      if (opt->n_push_routes > 0)
	{
	  vlib_cli_output (vm, "  Push Routes (%u):", opt->n_push_routes);
	  for (u32 i = 0; i < opt->n_push_routes; i++)
	    vlib_cli_output (vm, "    [%u] %U", i, format_fib_prefix,
			     &opt->push_routes[i]);
	}

      /* Show custom push options */
      if (opt->n_push_options > 0)
	{
	  vlib_cli_output (vm,
			   "  Custom Push Options (%u):", opt->n_push_options);
	  for (u32 i = 0; i < opt->n_push_options; i++)
	    vlib_cli_output (vm, "    [%u] %s", i, opt->push_options[i]);
	}

      /* Show redirect gateway */
      if (opt->redirect_gateway)
	vlib_cli_output (vm, "  Redirect Gateway: enabled (flags: 0x%x)",
			 opt->redirect_gateway_flags);
    }

  return 0;
}

/*?
 * Show OpenVPN configuration
 *
 * @cliexpar
 * @cliexstart{show ovpn}
 * show ovpn
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (ovpn_show_command, static) = {
  .path = "show ovpn",
  .short_help = "show ovpn",
  .function = ovpn_show_command_fn,
};

/*
 * CLI: ovpn create local <ip> port <port> [options...]
 * Creates an OpenVPN interface with full configuration options.
 */
static clib_error_t *
ovpn_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  ovpn_main_t *omp = &ovpn_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  ip_address_t local_addr = { 0 };
  u32 port = 1194;
  u8 *dev_name = 0;
  u8 *ca_cert = 0;
  u8 *server_cert = 0;
  u8 *server_key = 0;
  u8 *dh_params = 0;
  u8 *cipher = 0;
  u8 *auth = 0;
  u8 *tls_crypt_key = 0;
  u8 *tls_crypt_v2_key = 0;
  u8 *tls_auth_key = 0;
  u8 *secret_key = 0;
  ip_address_t pool_start, pool_end;
  fib_prefix_t server_addr;
  int got_local = 0;
  /* OpenVPN defaults */
  u32 max_clients = 1024;
  u32 keepalive_ping = 10;
  u32 keepalive_timeout = 120;
  u32 handshake_timeout = 60;
  u32 renegotiate_seconds = 3600;
  u32 tls_timeout = 2;
  u8 replay_protection = 1;
  u32 replay_window = 64;
  u32 replay_time = 15;
  u32 transition_window = 3600;
  u16 mtu = 1500;
  u8 is_tun = 1;
  u32 table_id = 0; /* FIB table ID (0 = default) */
  ovpn_options_t options;

  clib_memset (&pool_start, 0, sizeof (pool_start));
  clib_memset (&pool_end, 0, sizeof (pool_end));
  clib_memset (&server_addr, 0, sizeof (server_addr));
  clib_memset (&options, 0, sizeof (options));
  options.sw_if_index = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U", unformat_ip_address, &local_addr))
	got_local = 1;
      else if (unformat (line_input, "port %u", &port))
	;
      else if (unformat (line_input, "dev %s", &dev_name))
	;
      else if (unformat (line_input, "ca %s", &ca_cert))
	;
      else if (unformat (line_input, "cert %s", &server_cert))
	;
      else if (unformat (line_input, "key %s", &server_key))
	;
      else if (unformat (line_input, "dh %s", &dh_params))
	;
      else if (unformat (line_input, "cipher %s", &cipher))
	;
      else if (unformat (line_input, "auth %s", &auth))
	;
      else if (unformat (line_input, "tls-crypt %s", &tls_crypt_key))
	;
      else if (unformat (line_input, "tls-crypt-v2 %s", &tls_crypt_v2_key))
	;
      else if (unformat (line_input, "tls-auth %s", &tls_auth_key))
	;
      else if (unformat (line_input, "secret %s", &secret_key))
	;
      else if (unformat (line_input, "server %U/%d", unformat_ip4_address,
			 &server_addr.fp_addr.ip4, &server_addr.fp_len))
	server_addr.fp_proto = FIB_PROTOCOL_IP4;
      else if (unformat (line_input, "server %U/%d", unformat_ip6_address,
			 &server_addr.fp_addr.ip6, &server_addr.fp_len))
	server_addr.fp_proto = FIB_PROTOCOL_IP6;
      else if (unformat (line_input, "ifconfig-pool %U %U",
			 unformat_ip4_address, &pool_start.ip.ip4,
			 unformat_ip4_address, &pool_end.ip.ip4))
	{
	  pool_start.version = AF_IP4;
	  pool_end.version = AF_IP4;
	}
      else if (unformat (line_input, "max-clients %u", &max_clients))
	;
      else if (unformat (line_input, "keepalive %u %u", &keepalive_ping,
			 &keepalive_timeout))
	;
      else if (unformat (line_input, "hand-window %u", &handshake_timeout))
	;
      else if (unformat (line_input, "reneg-sec %u", &renegotiate_seconds))
	;
      else if (unformat (line_input, "tls-timeout %u", &tls_timeout))
	;
      else if (unformat (line_input, "replay-window %u %u", &replay_window,
			 &replay_time))
	;
      else if (unformat (line_input, "replay-window %u", &replay_window))
	;
      else if (unformat (line_input, "tun-mtu %u", &mtu))
	;
      else if (unformat (line_input, "fragment %u", &options.fragment_size))
	;
      else if (unformat (line_input, "dev-type tun"))
	is_tun = 1;
      else if (unformat (line_input, "dev-type tap"))
	is_tun = 0;
      else if (unformat (line_input, "table-id %u", &table_id))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!got_local)
    {
      error = clib_error_return (0, "local address required");
      goto done;
    }

  /* Check if port is already in use */
  if (vec_len (omp->instance_id_by_port) > port &&
      omp->instance_id_by_port[port] != ~0)
    {
      error = clib_error_return (0, "Port %u is already in use by instance %u",
				 port, omp->instance_id_by_port[port]);
      goto done;
    }

  /* Configure options */
  options.listen_port = (u16) port;
  options.proto = IP_PROTOCOL_UDP;
  options.mtu = mtu;
  options.is_tun = is_tun;

  /* Store server address */
  if (ip_addr_version (&local_addr) == AF_IP6)
    {
      server_addr.fp_proto = FIB_PROTOCOL_IP6;
      server_addr.fp_len = 128;
      clib_memcpy (&server_addr.fp_addr.ip6, &local_addr.ip.ip6,
		   sizeof (ip6_address_t));
    }
  else
    {
      server_addr.fp_proto = FIB_PROTOCOL_IP4;
      server_addr.fp_len = 32;
      server_addr.fp_addr.ip4.as_u32 = local_addr.ip.ip4.as_u32;
    }
  options.server_addr = server_addr;

  /* Set device name */
  if (dev_name)
    {
      options.dev_name = (char *) dev_name;
      dev_name = 0;
    }

  /* Load TLS-Crypt key if specified */
  if (tls_crypt_key)
    {
      error = ovpn_read_file_contents ((char *) tls_crypt_key,
				       &options.tls_crypt_key);
      if (error)
	{
	  error = clib_error_return (0, "failed to read TLS-Crypt key: %U",
				     format_clib_error, error);
	  goto done;
	}
    }

  /* Load TLS-Auth key if specified */
  if (tls_auth_key)
    {
      error =
	ovpn_read_file_contents ((char *) tls_auth_key, &options.tls_auth_key);
      if (error)
	{
	  error = clib_error_return (0, "failed to read TLS-Auth key: %U",
				     format_clib_error, error);
	  goto done;
	}
    }

  /* Load TLS-Crypt-V2 server key if specified */
  if (tls_crypt_v2_key)
    {
      error = ovpn_read_file_contents ((char *) tls_crypt_v2_key,
				       &options.tls_crypt_v2_key);
      if (error)
	{
	  error = clib_error_return (0, "failed to read TLS-Crypt-V2 key: %U",
				     format_clib_error, error);
	  goto done;
	}
    }

  /* Load certificates if specified */
  if (ca_cert)
    {
      error = ovpn_read_file_contents ((char *) ca_cert, &options.ca_cert);
      if (error)
	goto done;
    }
  if (server_cert)
    {
      error =
	ovpn_read_file_contents ((char *) server_cert, &options.server_cert);
      if (error)
	goto done;
    }
  if (server_key)
    {
      error =
	ovpn_read_file_contents ((char *) server_key, &options.server_key);
      if (error)
	goto done;
    }

  /* Set cipher */
  if (cipher)
    options.cipher_name = cipher;

  /* Set other options */
  options.max_clients = max_clients;
  options.keepalive_ping = keepalive_ping;
  options.keepalive_timeout = keepalive_timeout;
  options.handshake_window = handshake_timeout;
  options.renegotiate_seconds = renegotiate_seconds;
  options.tls_timeout = tls_timeout;
  options.replay_protection = replay_protection;
  options.replay_window = replay_window;
  options.replay_time = replay_time;
  options.transition_window = transition_window;
  if (pool_start.version != 0)
    options.pool_start = pool_start;
  if (pool_end.version != 0)
    options.pool_end = pool_end;

  /* Load static key if specified (--secret option) */
  if (secret_key)
    {
      u8 *key_contents = NULL;
      error = ovpn_read_file_contents ((char *) secret_key, &key_contents);
      if (error)
	{
	  error = clib_error_return (0, "failed to read static key file: %U",
				     format_clib_error, error);
	  goto done;
	}

      /* Allocate storage for parsed key */
      options.static_key = clib_mem_alloc (OVPN_STATIC_KEY_SIZE);
      if (!options.static_key)
	{
	  vec_free (key_contents);
	  error =
	    clib_error_return (0, "failed to allocate static key memory");
	  goto done;
	}

      /* Parse the static key file */
      int rv = ovpn_parse_static_key (key_contents, vec_len (key_contents),
				      options.static_key);
      vec_free (key_contents);
      if (rv < 0)
	{
	  clib_mem_free (options.static_key);
	  options.static_key = NULL;
	  error = clib_error_return (0, "failed to parse static key: %d", rv);
	  goto done;
	}

      options.static_key_mode = 1;
      options.static_key_direction = 0; /* Server mode = direction 0 */
    }

  /* Create the instance */
  u32 instance_id = ~0;
  u32 sw_if_index = ~0;
  int rv = ovpn_instance_create (vm, &local_addr, port, table_id, &options,
				 &instance_id, &sw_if_index);
  if (rv != 0)
    {
      error = clib_error_return (0, "failed to create instance: %d", rv);
      goto done;
    }

  vlib_cli_output (
    vm, "OpenVPN instance %u created: interface %s on port %u (table %u)",
    instance_id, options.dev_name ? options.dev_name : "ovpnX", port,
    table_id);

done:
  vec_free (dev_name);
  vec_free (ca_cert);
  vec_free (server_cert);
  vec_free (server_key);
  vec_free (dh_params);
  vec_free (cipher);
  vec_free (auth);
  vec_free (tls_crypt_key);
  vec_free (tls_crypt_v2_key);
  vec_free (tls_auth_key);
  vec_free (secret_key);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (ovpn_create_command, static) = {
  .path = "ovpn create",
  .short_help = "ovpn create local <ip> port <port> [dev <name>] "
		"[table-id <id>] [secret <keyfile>] "
		"[tls-crypt <key>] [tls-crypt-v2 <key>] [tls-auth <key>] "
		"[ca <cert>] [cert <cert>] [key <key>] [cipher <name>] "
		"[fragment <size>] [server <ip>/<len>]",
  .function = ovpn_create_command_fn,
};

/*
 * CLI: ovpn delete interface <name>
 * Deletes an OpenVPN interface.
 */
static clib_error_t *
ovpn_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected interface name");

  if (unformat (line_input, "interface %U", unformat_vnet_sw_interface,
		vnet_get_main (), &sw_if_index))
    ;
  else
    {
      error = clib_error_return (0, "unknown input `%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  int rv = ovpn_instance_delete (vm, sw_if_index);
  if (rv != 0)
    {
      error = clib_error_return (
	0, "interface not found or not an OpenVPN interface");
      goto done;
    }

  vlib_cli_output (vm, "OpenVPN interface deleted");

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (ovpn_delete_command, static) = {
  .path = "ovpn delete",
  .short_help = "ovpn delete interface <interface>",
  .function = ovpn_delete_command_fn,
};

/*
 * Helper function to convert peer state to string
 */
static const char *
ovpn_peer_state_to_string (ovpn_peer_state_t state)
{
  switch (state)
    {
    case OVPN_PEER_STATE_INITIAL:
      return "initial";
    case OVPN_PEER_STATE_HANDSHAKE:
      return "handshake";
    case OVPN_PEER_STATE_ESTABLISHED:
      return "established";
    case OVPN_PEER_STATE_REKEYING:
      return "rekeying";
    case OVPN_PEER_STATE_DEAD:
      return "dead";
    default:
      return "unknown";
    }
}

/*
 * CLI: show ovpn peers [interface <interface>] [peer-id <id>] [verbose]
 * Display connected OpenVPN peers with their status and statistics.
 */
static clib_error_t *
ovpn_show_peers_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  ovpn_main_t *omp = &ovpn_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  u32 filter_peer_id = ~0;
  u8 verbose = 0;
  f64 now = vlib_time_now (vm);

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "interface %U", unformat_vnet_sw_interface,
			omp->vnm, &sw_if_index))
	    ;
	  else if (unformat (line_input, "peer-id %u", &filter_peer_id))
	    ;
	  else if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else
	    {
	      unformat_free (line_input);
	      return clib_error_return (0, "unknown input: %U",
					format_unformat_error, line_input);
	    }
	}
      unformat_free (line_input);
    }

  u32 total_peers = 0;
  ovpn_instance_t *inst;

  pool_foreach (inst, omp->instances)
    {
      if (!inst->is_active)
	continue;

      /* Filter by interface if specified */
      if (sw_if_index != ~0 && inst->sw_if_index != sw_if_index)
	continue;

      ovpn_peer_db_t *peer_db = &inst->multi_context.peer_db;
      u32 num_peers = pool_elts (peer_db->peers);

      if (num_peers == 0)
	continue;

      vlib_cli_output (vm, "Instance %u (sw_if_index %u, port %u):",
		       inst->instance_id, inst->sw_if_index, inst->local_port);

      ovpn_peer_t *peer;
      pool_foreach (peer, peer_db->peers)
	{
	  /* Filter by peer-id if specified */
	  if (filter_peer_id != ~0 && peer->peer_id != filter_peer_id)
	    continue;

	  total_peers++;

	  f64 uptime = peer->established_time > 0 ?
			 now - peer->established_time :
			 0;
	  f64 idle = now - peer->last_rx_time;

	  vlib_cli_output (vm, "  Peer %u:", peer->peer_id);
	  vlib_cli_output (vm, "    State: %s",
			   ovpn_peer_state_to_string (peer->state));
	  vlib_cli_output (vm, "    Remote: %U:%u", format_ip_address,
			   &peer->remote_addr, peer->remote_port);

	  if (peer->virtual_ip_set)
	    vlib_cli_output (vm, "    Virtual IP: %U", format_ip_address,
			     &peer->virtual_ip);

	  vlib_cli_output (vm, "    RX: %llu bytes / %llu packets",
			   peer->rx_bytes, peer->rx_packets);
	  vlib_cli_output (vm, "    TX: %llu bytes / %llu packets",
			   peer->tx_bytes, peer->tx_packets);

	  if (peer->state == OVPN_PEER_STATE_ESTABLISHED)
	    {
	      vlib_cli_output (vm, "    Uptime: %.1f seconds", uptime);
	      vlib_cli_output (vm, "    Idle: %.1f seconds", idle);
	    }

	  if (verbose)
	    {
	      vlib_cli_output (vm, "    Session ID: %02x%02x%02x%02x%02x%02x%02x%02x",
			       peer->session_id.id[0], peer->session_id.id[1],
			       peer->session_id.id[2], peer->session_id.id[3],
			       peer->session_id.id[4], peer->session_id.id[5],
			       peer->session_id.id[6], peer->session_id.id[7]);
	      vlib_cli_output (vm, "    Remote Session ID: %02x%02x%02x%02x%02x%02x%02x%02x",
			       peer->remote_session_id.id[0],
			       peer->remote_session_id.id[1],
			       peer->remote_session_id.id[2],
			       peer->remote_session_id.id[3],
			       peer->remote_session_id.id[4],
			       peer->remote_session_id.id[5],
			       peer->remote_session_id.id[6],
			       peer->remote_session_id.id[7]);
	      vlib_cli_output (vm, "    Current Key Slot: %u",
			       peer->current_key_slot);
	      vlib_cli_output (vm, "    Generation: %u", peer->generation);

	      if (peer->keys[OVPN_KEY_SLOT_PRIMARY].is_active)
		vlib_cli_output (vm, "    Primary Key ID: %u",
				 peer->keys[OVPN_KEY_SLOT_PRIMARY].key_id);
	      if (peer->keys[OVPN_KEY_SLOT_SECONDARY].is_active)
		vlib_cli_output (vm, "    Secondary Key ID: %u",
				 peer->keys[OVPN_KEY_SLOT_SECONDARY].key_id);
	    }
	}
    }

  vlib_cli_output (vm, "Total peers: %u", total_peers);
  return 0;
}

/*?
 * Show OpenVPN peers
 *
 * @cliexpar
 * @cliexstart{show ovpn peers}
 * show ovpn peers [interface <interface>] [peer-id <id>] [verbose]
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (ovpn_show_peers_command, static) = {
  .path = "show ovpn peers",
  .short_help = "show ovpn peers [interface <interface>] [peer-id <id>] [verbose]",
  .function = ovpn_show_peers_command_fn,
};

/*
 * CLI: ovpn peer kill <peer-id> [interface <interface>]
 * Disconnect a specific OpenVPN peer.
 */
static clib_error_t *
ovpn_peer_kill_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  ovpn_main_t *omp = &ovpn_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 peer_id = ~0;
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u", &peer_id))
	;
      else if (unformat (line_input, "interface %U", unformat_vnet_sw_interface,
			 omp->vnm, &sw_if_index))
	;
      else
	{
	  error = clib_error_return (0, "unknown input: %U",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (peer_id == ~0)
    {
      error = clib_error_return (0, "peer-id is required");
      goto done;
    }

  /* Find and kill the peer */
  u8 found = 0;
  ovpn_instance_t *inst;

  pool_foreach (inst, omp->instances)
    {
      if (!inst->is_active)
	continue;

      /* Filter by interface if specified */
      if (sw_if_index != ~0 && inst->sw_if_index != sw_if_index)
	continue;

      ovpn_peer_db_t *peer_db = &inst->multi_context.peer_db;
      ovpn_peer_t *peer = ovpn_peer_get (peer_db, peer_id);

      if (peer)
	{
	  found = 1;
	  vlib_cli_output (vm, "Killing peer %u on instance %u", peer_id,
			   inst->instance_id);

	  /* Mark as dead and let periodic process clean up */
	  peer->state = OVPN_PEER_STATE_DEAD;
	  ovpn_peer_delete (peer_db, peer_id);
	  break;
	}
    }

  if (!found)
    {
      error = clib_error_return (0, "peer %u not found", peer_id);
    }

done:
  unformat_free (line_input);
  return error;
}

/*?
 * Kill (disconnect) an OpenVPN peer
 *
 * @cliexpar
 * @cliexstart{ovpn peer kill}
 * ovpn peer kill <peer-id> [interface <interface>]
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (ovpn_peer_kill_command, static) = {
  .path = "ovpn peer kill",
  .short_help = "ovpn peer kill <peer-id> [interface <interface>]",
  .function = ovpn_peer_kill_command_fn,
};

/*
 * CLI: show ovpn stats [interface <interface>]
 * Display OpenVPN statistics.
 */
static clib_error_t *
ovpn_show_stats_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  ovpn_main_t *omp = &ovpn_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "interface %U", unformat_vnet_sw_interface,
			omp->vnm, &sw_if_index))
	    ;
	  else
	    {
	      unformat_free (line_input);
	      return clib_error_return (0, "unknown input: %U",
					format_unformat_error, line_input);
	    }
	}
      unformat_free (line_input);
    }

  ovpn_instance_t *inst;
  u64 total_rx_bytes = 0, total_tx_bytes = 0;
  u64 total_rx_packets = 0, total_tx_packets = 0;
  u32 total_peers = 0, total_established = 0;

  pool_foreach (inst, omp->instances)
    {
      if (!inst->is_active)
	continue;

      /* Filter by interface if specified */
      if (sw_if_index != ~0 && inst->sw_if_index != sw_if_index)
	continue;

      ovpn_peer_db_t *peer_db = &inst->multi_context.peer_db;
      u32 num_peers = pool_elts (peer_db->peers);
      u32 num_established = 0;
      u64 inst_rx_bytes = 0, inst_tx_bytes = 0;
      u64 inst_rx_packets = 0, inst_tx_packets = 0;

      ovpn_peer_t *peer;
      pool_foreach (peer, peer_db->peers)
	{
	  inst_rx_bytes += peer->rx_bytes;
	  inst_tx_bytes += peer->tx_bytes;
	  inst_rx_packets += peer->rx_packets;
	  inst_tx_packets += peer->tx_packets;

	  if (peer->state == OVPN_PEER_STATE_ESTABLISHED)
	    num_established++;
	}

      vlib_cli_output (vm, "Instance %u (sw_if_index %u, port %u):",
		       inst->instance_id, inst->sw_if_index, inst->local_port);
      vlib_cli_output (vm, "  Peers: %u total, %u established", num_peers,
		       num_established);
      vlib_cli_output (vm, "  RX: %llu bytes, %llu packets", inst_rx_bytes,
		       inst_rx_packets);
      vlib_cli_output (vm, "  TX: %llu bytes, %llu packets", inst_tx_bytes,
		       inst_tx_packets);
      vlib_cli_output (vm, "  Pending Connections: %u",
		       pool_elts (inst->multi_context.pending_db.connections));

      total_peers += num_peers;
      total_established += num_established;
      total_rx_bytes += inst_rx_bytes;
      total_tx_bytes += inst_tx_bytes;
      total_rx_packets += inst_rx_packets;
      total_tx_packets += inst_tx_packets;
    }

  if (sw_if_index == ~0 && pool_elts (omp->instances) > 1)
    {
      vlib_cli_output (vm, "");
      vlib_cli_output (vm, "Total:");
      vlib_cli_output (vm, "  Instances: %u", pool_elts (omp->instances));
      vlib_cli_output (vm, "  Peers: %u total, %u established", total_peers,
		       total_established);
      vlib_cli_output (vm, "  RX: %llu bytes, %llu packets", total_rx_bytes,
		       total_rx_packets);
      vlib_cli_output (vm, "  TX: %llu bytes, %llu packets", total_tx_bytes,
		       total_tx_packets);
    }

  return 0;
}

/*?
 * Show OpenVPN statistics
 *
 * @cliexpar
 * @cliexstart{show ovpn stats}
 * show ovpn stats [interface <interface>]
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (ovpn_show_stats_command, static) = {
  .path = "show ovpn stats",
  .short_help = "show ovpn stats [interface <interface>]",
  .function = ovpn_show_stats_command_fn,
};

/*
 * CLI: clear ovpn stats [interface <interface>]
 * Clear OpenVPN statistics.
 */
static clib_error_t *
ovpn_clear_stats_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  ovpn_main_t *omp = &ovpn_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "interface %U", unformat_vnet_sw_interface,
			omp->vnm, &sw_if_index))
	    ;
	  else
	    {
	      unformat_free (line_input);
	      return clib_error_return (0, "unknown input: %U",
					format_unformat_error, line_input);
	    }
	}
      unformat_free (line_input);
    }

  u32 cleared_peers = 0;
  ovpn_instance_t *inst;

  pool_foreach (inst, omp->instances)
    {
      if (!inst->is_active)
	continue;

      /* Filter by interface if specified */
      if (sw_if_index != ~0 && inst->sw_if_index != sw_if_index)
	continue;

      ovpn_peer_db_t *peer_db = &inst->multi_context.peer_db;
      ovpn_peer_t *peer;

      pool_foreach (peer, peer_db->peers)
	{
	  peer->rx_bytes = 0;
	  peer->tx_bytes = 0;
	  peer->rx_packets = 0;
	  peer->tx_packets = 0;
	  peer->bytes_since_rekey = 0;
	  peer->packets_since_rekey = 0;
	  cleared_peers++;
	}
    }

  vlib_cli_output (vm, "Cleared statistics for %u peers", cleared_peers);
  return 0;
}

/*?
 * Clear OpenVPN statistics
 *
 * @cliexpar
 * @cliexstart{clear ovpn stats}
 * clear ovpn stats [interface <interface>]
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (ovpn_clear_stats_command, static) = {
  .path = "clear ovpn stats",
  .short_help = "clear ovpn stats [interface <interface>]",
  .function = ovpn_clear_stats_command_fn,
};

/*
 * Plugin initialization
 */
static clib_error_t *
ovpn_init (vlib_main_t *vm)
{
  ovpn_main_t *omp = &ovpn_main;
  clib_error_t *error = NULL;

  omp->vm = vm;
  omp->vnm = vnet_get_main ();

  /* Initialize instance pool and lookups */
  omp->instances = NULL;
  omp->instance_id_by_port = NULL;
  omp->instance_by_sw_if_index = hash_create (0, sizeof (uword));

  /* Store node indices */
  omp->ovpn4_input_node_index = ovpn4_input_node.index;
  omp->ovpn6_input_node_index = ovpn6_input_node.index;
  omp->ovpn4_output_node_index = ovpn4_output_node.index;
  omp->ovpn6_output_node_index = ovpn6_output_node.index;

  /* Initialize frame queues for handoff */
  omp->in4_fq_index = vlib_frame_queue_main_init (ovpn4_input_node.index, 0);
  omp->in6_fq_index = vlib_frame_queue_main_init (ovpn6_input_node.index, 0);
  omp->out4_fq_index = vlib_frame_queue_main_init (ovpn4_output_node.index, 0);
  omp->out6_fq_index = vlib_frame_queue_main_init (ovpn6_output_node.index, 0);

  /* Allocate high-priority FIB source for tunnel routes */
  omp->fib_src_hi =
    fib_source_allocate ("ovpn-hi", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_API);

  /* Initialize crypto subsystem */
  error = ovpn_crypto_init (vm);
  if (error)
    return error;

  /* Initialize management interface subsystem */
  ovpn_mgmt_init (vm);

  return 0;
}

VLIB_INIT_FUNCTION (ovpn_init);

/*
 * Periodic process for:
 * - Checking rekey timers
 * - Expiring pending connections
 * - Cleaning up dead peers
 */
static uword
ovpn_periodic_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		       vlib_frame_t *f)
{
  ovpn_main_t *omp = &ovpn_main;
  f64 now;

  while (1)
    {
      /* Sleep for 1 second between checks */
      vlib_process_wait_for_event_or_clock (vm, 1.0);

      /* Handle exit-notify events from data plane */
      {
	uword event_type;
	uword *event_data = 0;

	while ((event_type = vlib_process_get_events (vm, &event_data)) != ~0)
	  {
	    if (event_type == OVPN_PROCESS_EVENT_EXIT_NOTIFY)
	      {
		for (u32 i = 0; i < vec_len (event_data); i++)
		  {
		    u32 data = event_data[i];
		    u32 inst_id = OVPN_EXIT_NOTIFY_INST_ID (data);
		    u32 peer_id = OVPN_EXIT_NOTIFY_PEER_ID (data);

		    ovpn_instance_t *inst = ovpn_instance_get (inst_id);
		    if (inst && inst->is_active)
		      {
			ovpn_peer_t *peer =
			  ovpn_peer_get (&inst->multi_context.peer_db, peer_id);
			if (peer &&
			    peer->state == OVPN_PEER_STATE_ESTABLISHED)
			  {
			    peer->state = OVPN_PEER_STATE_DEAD;
			    ovpn_peer_delete (&inst->multi_context.peer_db,
					      peer_id);
			  }
		      }
		  }
	      }
	    else if (event_type == OVPN_PROCESS_EVENT_ADDR_UPDATE)
	      {
		/* Process address updates with worker barrier */
		vlib_worker_thread_barrier_sync (vm);
		for (u32 i = 0; i < vec_len (event_data); i++)
		  {
		    u32 data = event_data[i];
		    u32 inst_id = OVPN_ADDR_UPDATE_INST_ID (data);
		    u32 peer_id = OVPN_ADDR_UPDATE_PEER_ID (data);

		    ovpn_instance_t *inst = ovpn_instance_get (inst_id);
		    if (inst && inst->is_active)
		      {
			ovpn_peer_t *peer =
			  ovpn_peer_get (&inst->multi_context.peer_db, peer_id);
			if (peer)
			  {
			    ovpn_peer_update_remote (
			      &inst->multi_context.peer_db, peer,
			      &peer->pending_remote_addr,
			      peer->pending_remote_port);
			  }
		      }
		  }
		vlib_worker_thread_barrier_release (vm);
	      }
	    else if (event_type == OVPN_PROCESS_EVENT_CLIENT_AUTH)
	      {
		/*
		 * Process client auth approvals from management interface.
		 * Continue handshake for peers in PENDING_AUTH state.
		 */
		for (u32 i = 0; i < vec_len (event_data); i++)
		  {
		    u32 data = event_data[i];
		    u32 inst_id = OVPN_CLIENT_AUTH_INST_ID (data);
		    u32 peer_id = OVPN_CLIENT_AUTH_PEER_ID (data);

		    ovpn_instance_t *inst = ovpn_instance_get (inst_id);
		    if (inst && inst->is_active)
		      {
			ovpn_peer_t *peer =
			  ovpn_peer_get (&inst->multi_context.peer_db, peer_id);
			if (peer &&
			    peer->state == OVPN_PEER_STATE_PENDING_AUTH)
			  {
			    /*
			     * Auth approved - continue handshake.
			     * Set state back to HANDSHAKE and process
			     * the pending TLS data.
			     */
			    peer->state = OVPN_PEER_STATE_HANDSHAKE;
			  }
		      }
		  }
	      }
	    vec_reset_length (event_data);
	  }
	vec_free (event_data);
      }

      if (pool_elts (omp->instances) == 0)
	continue;

      now = vlib_time_now (vm);

      /* Iterate over all active instances */
      ovpn_instance_t *inst;
      pool_foreach (inst, omp->instances)
	{
	  if (!inst->is_active)
	    continue;

	  /* Expire old pending connections */
	  ovpn_pending_db_expire (&inst->multi_context.pending_db, now);

	  /* Cleanup expired keys (lame duck keys after transition window) */
	  ovpn_peer_db_cleanup_expired_keys (vm, &inst->multi_context.peer_db,
					     now);

	  /*
	   * Process control channel retransmissions.
	   * Check all pending connections and established peers for
	   * control packets that need retransmitting (timeout expired).
	   */
	  ovpn_control_channel_retransmit (vm, inst);

	  /* Get keepalive settings */
	  f64 ping_interval = inst->options.keepalive_ping > 0 ?
				(f64) inst->options.keepalive_ping :
				10.0;
	  f64 ping_timeout = inst->options.keepalive_timeout > 0 ?
			       (f64) inst->options.keepalive_timeout :
			       60.0;

	  /* Check each peer */
	  ovpn_peer_t *peer;
	  u32 *peers_to_delete = NULL;

	  pool_foreach (peer, inst->multi_context.peer_db.peers)
	    {
	      /* Skip non-established peers */
	      if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
		continue;

	      /*
	       * Check keepalive timeout
	       * If we haven't received any packet from the peer within the
	       * timeout period, mark the peer as dead.
	       */
	      f64 last_activity = peer->last_rx_time;
	      f64 idle_time = now - last_activity;

	      if (idle_time > ping_timeout)
		{
		  /*
		   * Peer has exceeded keepalive timeout
		   * Mark as dead for cleanup
		   */
		  peer->state = OVPN_PEER_STATE_DEAD;
		  vec_add1 (peers_to_delete, peer->peer_id);
		  continue;
		}

	      /*
	       * Check if we should send a ping
	       * Send ping if we haven't sent anything recently
	       */
	      f64 tx_idle_time = now - peer->last_tx_time;
	      if (tx_idle_time >= ping_interval)
		{
		  /*
		   * Send ping packet on data channel
		   * OpenVPN ping is sent as encrypted data with magic pattern
		   */
		  ovpn_peer_send_ping (vm, peer);
		}

	      /* Check if rekey is needed (time, bytes, or packets) */
	      if (ovpn_peer_needs_rekey (peer, now,
					 inst->options.renegotiate_bytes,
					 inst->options.renegotiate_packets))
		{
		  /* Start server-initiated rekey */
		  u8 new_key_id = ovpn_peer_next_key_id (peer);
		  int rv = ovpn_peer_start_rekey (vm, peer, inst->ptls_ctx,
						  new_key_id);
		  if (rv == 0)
		    {
		      peer->rekey_initiated = 1;
		      /* Send SOFT_RESET to client */
		      if (peer->tls_ctx)
			{
			  ovpn_reli_buffer_t *buf;
			  buf = ovpn_reliable_get_buf_output_sequenced (
			    peer->tls_ctx->send_reliable);
			  if (buf)
			    {
			      ovpn_buf_init (buf, 128);
			      ovpn_reliable_mark_active_outgoing (
				peer->tls_ctx->send_reliable, buf,
				OVPN_OP_CONTROL_SOFT_RESET_V1);
			    }
			}
		    }
		}
	    }

	  /* Clean up dead peers */
	  for (u32 i = 0; i < vec_len (peers_to_delete); i++)
	    {
	      ovpn_peer_delete (&inst->multi_context.peer_db,
				peers_to_delete[i]);
	    }
	  vec_free (peers_to_delete);

	  /* Process management interface bytecount notifications */
	  ovpn_mgmt_t *mgmt = ovpn_mgmt_get_by_instance (inst->instance_id);
	  if (mgmt && mgmt->is_active)
	    ovpn_mgmt_process_bytecount (mgmt, now);

	  /*
	   * Periodic save of ifconfig-pool-persist file
	   * Only save if:
	   *   - persist is configured
	   *   - data is dirty (something changed)
	   *   - enough time has passed (ifconfig_pool_persist_seconds)
	   *
	   * If ifconfig_pool_persist_seconds == 0, save immediately on change.
	   * Otherwise, save at most every N seconds.
	   */
	  if (inst->multi_context.peer_db.persist_dirty &&
	      inst->multi_context.peer_db.persist_file_path)
	    {
	      f64 save_interval =
		(f64) inst->options.ifconfig_pool_persist_seconds;
	      f64 time_since_save =
		now - inst->multi_context.peer_db.persist_last_save_time;

	      if (save_interval == 0 || time_since_save >= save_interval)
		{
		  ovpn_peer_persist_save (&inst->multi_context.peer_db);
		  inst->multi_context.peer_db.persist_last_save_time = now;
		}
	    }
	}
    }

  return 0;
}

VLIB_REGISTER_NODE (ovpn_periodic_node) = {
  .function = ovpn_periodic_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ovpn-periodic",
};

/*
 * Plugin registration
 */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "OpenVPN Protocol",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
