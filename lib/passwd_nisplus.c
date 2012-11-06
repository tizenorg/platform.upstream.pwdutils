/* Copyright (C) 2002, 2005 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@thkukuk.de>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <rpc/key_prot.h>
#include <rpc/des_crypt.h>
#include <rpcsvc/nis.h>

#include <security/_pam_macros.h>
#include <security/pam_modules.h>

#include "i18n.h"
#include "public.h"
#include "nispasswd.h"

/* This is in glibc, but not in the headers */
extern int key_get_conv (char *pkey, des_block *deskey);

static bool_t
__pam_xdr_nispasswd_status (XDR *xdrs, nispasswd_status *objp)
{
  if (!xdr_enum(xdrs, (enum_t *)objp))
    return (FALSE);
  return (TRUE);
}

static bool_t
__pam_xdr_nispasswd_code (XDR *xdrs, nispasswd_code *objp)
{
  if (!xdr_enum(xdrs, (enum_t *)objp)) {
    return (FALSE);
  }
  return (TRUE);
}

static bool_t
__pam_xdr_nispasswd_field (XDR *xdrs, nispasswd_field *objp)
{
  if (!xdr_enum(xdrs, (enum_t *)objp)) {
    return (FALSE);
  }
  return (TRUE);
}

static bool_t
__pam_xdr_nispasswd_error (XDR *xdrs, nispasswd_error *objp)
{
  if (!__pam_xdr_nispasswd_field(xdrs, &objp->npd_field)) {
    return (FALSE);
  }
  if (!__pam_xdr_nispasswd_code(xdrs, &objp->npd_code)) {
    return (FALSE);
  }
  if (!xdr_pointer(xdrs, (char **)&objp->next, sizeof(nispasswd_error),
		   (xdrproc_t)__pam_xdr_nispasswd_error)) {
    return (FALSE);
  }
  return (TRUE);
}

static bool_t
__pam_xdr_passwd_info (XDR *xdrs, passwd_info *objp)
{
  if (!xdr_string(xdrs, &objp->pw_gecos, ~0)) {
    return (FALSE);
  }
  if (!xdr_string(xdrs, &objp->pw_shell, ~0)) {
    return (FALSE);
  }
  return (TRUE);
}

static bool_t
__pam_xdr_npd_request(XDR *xdrs, npd_request *objp)
{
  if (!xdr_string(xdrs, &objp->username, ~0)) {
    return (FALSE);
  }
  if (!xdr_string(xdrs, &objp->domain, ~0)) {
    return (FALSE);
  }
  if (!xdr_string(xdrs, &objp->key_type, ~0)) {
    return (FALSE);
  }
  if (!xdr_array(xdrs, (char **)&objp->user_pub_key.user_pub_key_val,
		 (u_int *)&objp->user_pub_key.user_pub_key_len, ~0,
		 sizeof(u_char), (xdrproc_t)xdr_u_char))
    return (FALSE);

  if (!xdr_array(xdrs, (char **)&objp->npd_authpass.npd_authpass_val,
		 (u_int *)&objp->npd_authpass.npd_authpass_len, ~0,
		 sizeof(u_char), (xdrproc_t)xdr_u_char))
    return (FALSE);

  if (!xdr_u_int (xdrs, &objp->ident))
    return (FALSE);

  return (TRUE);
}


static bool_t
__pam_xdr_passbuf (XDR *xdrs, passbuf objp)
{
  if (!xdr_opaque(xdrs, objp, __NPD_MAXPASSBYTES)) {
    return (FALSE);
  }
  return (TRUE);
}

static bool_t
__pam_xdr_npd_newpass (XDR *xdrs, npd_newpass *objp)
{
  if (!xdr_u_int(xdrs, &objp->npd_xrandval)) {
    return (FALSE);
  }
  if (!__pam_xdr_passbuf(xdrs, objp->pass)) {
    return (FALSE);
  }
  return (TRUE);
}

static bool_t
__pam_xdr_npd_update (XDR *xdrs, npd_update *objp)
{
  if (!xdr_u_int(xdrs, &objp->ident)) {
    return (FALSE);
  }
  if (!__pam_xdr_npd_newpass(xdrs, &objp->xnewpass)) {
    return (FALSE);
  }
  if (!__pam_xdr_passwd_info(xdrs, &objp->pass_info)) {
    return (FALSE);
  }
  return (TRUE);
}

static bool_t
__pam_xdr_nispasswd_verf (XDR *xdrs, nispasswd_verf *objp)
{
  if (!xdr_u_int (xdrs, &objp->npd_xid)) {
    return (FALSE);
  }
  if (!xdr_u_int (xdrs, &objp->npd_xrandval)) {
    return (FALSE);
  }
  return (TRUE);
}

static bool_t
__pam_xdr_nispasswd_authresult (XDR *xdrs, nispasswd_authresult *objp)
{
  if (!__pam_xdr_nispasswd_status(xdrs, &objp->status)) {
    return (FALSE);
  }
  switch (objp->status) {
  case NPD_SUCCESS:
  case NPD_TRYAGAIN:
    if (!__pam_xdr_nispasswd_verf(xdrs,
				  &objp->nispasswd_authresult_u.npd_verf))
      return FALSE;
    break;
  default:
    if (!__pam_xdr_nispasswd_code(xdrs,
				  &objp->nispasswd_authresult_u.npd_err))
      return (FALSE);
    break;
  }
  return (TRUE);
}

static bool_t
__pam_xdr_nispasswd_updresult (XDR *xdrs, nispasswd_updresult *objp)
{
  if (!__pam_xdr_nispasswd_status (xdrs, &objp->status))
    return (FALSE);
  switch (objp->status)
    {
    case NPD_PARTIALSUCCESS:
      if (!__pam_xdr_nispasswd_error (xdrs,
				      &objp->nispasswd_updresult_u.reason))
        return (FALSE);
      break;
    case NPD_FAILED:
      if (!__pam_xdr_nispasswd_code (xdrs,
				     &objp->nispasswd_updresult_u.npd_err))
        return (FALSE);
      break;
    default:
      break;
    }
  return (TRUE);
}

static const char *
npderr2str (nispasswd_code error)
{
  switch (error)
    {
    case NPD_NOTMASTER:
      return "Server is not master of this domain";
    case NPD_NOSUCHENTRY:
      return "No passwd entry exists for this user";
    case NPD_IDENTINVALID:
      return "Identifier invalid";
    case NPD_NOPASSWD:
      return "No password stored";
    case NPD_NOSHDWINFO:
      return "No shadow information stored";
    case NPD_SHDWCORRUPT:
      return "Shadow information corrupted";
    case NPD_NOTAGED:
      return "Passwd has not aged sufficiently";
    case NPD_CKGENFAILED:
      return "Common key could not be generated";
    case NPD_VERFINVALID:
      return "Verifier mismatch";
    case NPD_PASSINVALID:
      return "All auth attempts incorrect";
    case NPD_ENCRYPTFAIL:
      return "Encryption failed";
    case NPD_DECRYPTFAIL:
      return "Decryption failed";
    case NPD_KEYSUPDATED:
      return "New key-pair generated for user";
    case NPD_KEYNOTREENC:
      return "Could not reencrypt secret key";
    case NPD_PERMDENIED:
      return "Permission denied";
    case NPD_SRVNOTRESP:
      return "Server not responding";
    case NPD_NISERROR:
      return "NIS+ server error";
    case NPD_SYSTEMERR:
      return "System error";
    case NPD_BUFTOOSMALL:
      return "Buffer too small";
    case NPD_INVALIDARGS:
      return "Invalid args to function";
    default:
      return "Unknown error!";
    }
}


#define NISENTRYVAL(col,obj) \
        ((obj)->EN_data.en_cols.en_cols_val[(col)].ec_value.ec_value_val)
#define NISENTRYLEN(col,obj) \
        ((obj)->EN_data.en_cols.en_cols_val[(col)].ec_value.ec_value_len)
#define NISENTRYFLAG(col,res) \
        ((obj)->EN_data.en_cols.en_cols_val[(col)].ec_flags)

static int
update_npd (nis_object *obj, user_t *data)
{
  nis_server **server;
  CLIENT *clnt;
  struct timeval timeout;
  char oldpwd[17];
  npd_request request;
  npd_update update;
  nispasswd_authresult result;
  nispasswd_updresult updresult;
  char pkey_host[HEXKEYBYTES + 1];
  char pkey_user[HEXKEYBYTES + 1];
  char skey_data[HEXKEYBYTES + 1];
  char usernetname[MAXNETNAMELEN + 1], servernetname[MAXNETNAMELEN + 1];
  des_block CK;
  const char *masterhost;
  des_block cryptbuf;
  char ivec[8];
  u_int32_t *ixdr;
  int error;
  char *cp;

  /* build netname for user or if caller == root, host */
  if (getuid () == 0 && strncmp (NISENTRYVAL(0,obj), "root",
				 NISENTRYLEN(0,obj)) == 0)
    {
      char hostname[MAXHOSTNAMELEN + 1];

      if (gethostname (hostname, MAXHOSTNAMELEN) != 0)
	{
	  fprintf (stderr, _("Could not determine hostname!\n"));
	  return -1;
	}
      host2netname (usernetname, hostname, NULL);
    }
  else
    user2netname (usernetname, getuid (), NULL);

  /* get old password for decrypting secret key and further use. */
  memset (oldpwd, '\0', sizeof (oldpwd));
  strncpy (oldpwd, data->oldclearpwd, sizeof (oldpwd) -1);
  if (!getsecretkey (usernetname, skey_data, oldpwd))
    {
      if (!getsecretkey (usernetname, skey_data,
			 getpass ("Enter RPC secure password: ")))
	{
	  fprintf (stderr, _("Can't find %s's secret key\n"), usernetname);
	  return -1;
	}
    }

  /* fill in request struct */
  memset (&request, '\0', sizeof (request));
  request.ident = 0;
  request.key_type = strdup ("DES");
  request.domain = strdup (nis_domain_of (obj->zo_domain));
  request.username = strndup (NISENTRYVAL(0,obj), NISENTRYLEN(0,obj));

  /* get publickey of the user */
  memset (pkey_user, '\0', sizeof (pkey_user));
  if (getpublickey (usernetname, pkey_user) == 0 || pkey_user[0] == '\0')
    {
      fprintf (stderr, _("Could not get public key for %s!\n"), usernetname);
      return -1;
    }
  request.user_pub_key.user_pub_key_len = HEXKEYBYTES;
  request.user_pub_key.user_pub_key_val = (unsigned char *) pkey_user;
  /* get publickey of the server running rpc.nispasswdd. For that,
     we have to find the name of the master server for the user domain. */
  server = nis_getservlist (request.domain);
  if (server[0] == NULL)
    {
      fprintf (stderr, _("Could not determine the NIS+ root server!\n"));
      return -1;
    }
  masterhost = strdup (server[0]->name);
  cp = strchr (masterhost, '.');
  *cp = '\0';
  nis_freeservlist (server);
  host2netname (servernetname, masterhost, NULL);
  memset (pkey_host, '\0', sizeof (pkey_host));
  if (getpublickey (servernetname, pkey_host) == 0 || pkey_host[0] == '\0')
    {
      fprintf (stderr, _("Could not get public key for %s!\n"), servernetname);
      return -1;
    }

  /* Generate common DES key from public server key and secret user key */
  if (key_get_conv (pkey_host, &CK) != 0)
    {
      fprintf (stderr, _("Could not create conversion key!\n"));
      return -1;
    }

  /* encrypt old clear password. Don't know why Sun needs 16 byte,
     normaly a password could only be 8 byte. And later in the protocol
     SUN allows only 12 byte. */
  memset (ivec, 0, 8);
  error = cbc_crypt ((char *) &CK, oldpwd,
		   16, DES_ENCRYPT | DES_HW, ivec);
  if (DES_FAILED (error))
    {
      fprintf (stderr, _("DES encryption failure\n"));
      return -1;
    }
  request.npd_authpass.npd_authpass_len = 16;
  request.npd_authpass.npd_authpass_val = (unsigned char *) oldpwd;

  /* Try to authenticate us and the server.
     XXX This should be done in a loop,
     since the server could be bussy or the password wrong */
  clnt = clnt_create (masterhost, NISPASSWD_PROG, NISPASSWD_VERS, "tcp");
  if (clnt == NULL)
    {
      fprintf (stderr, _("rpc.nispasswd not running on %s?\n"), masterhost);
      return -1;
    }
  memset ((char *) &result, 0, sizeof (result));
  timeout.tv_sec = 25;
  timeout.tv_usec = 0;
  error = clnt_call (clnt, NISPASSWD_AUTHENTICATE,
		     (xdrproc_t) __pam_xdr_npd_request, (caddr_t) &request,
		     (xdrproc_t) __pam_xdr_nispasswd_authresult,
		     (caddr_t) &result, timeout);

  if (error)
    {
      clnt_perrno (error);
      fputs ("\n", stderr);
      return -1;
    }

  if (result.status != NPD_SUCCESS)
    {
      if (result.status == NPD_TRYAGAIN)
	fprintf (stderr, _("ERROR: password incorrect, try again\n"));
      else
	fprintf (stderr, _("ERROR: %s\n       password not changed\n"),
			 npderr2str (result.nispasswd_authresult_u.npd_err));
      return -1;
    }

  /* Decrypt the ID and the random value. Not easy, since Sparc's are
     big endian, i?86 little endian, we have to revert to big endian
     for decrypt */
  memset (&cryptbuf, '\0', sizeof (cryptbuf));
  ixdr = &cryptbuf.key.high;
  IXDR_PUT_U_INT32 (ixdr, result.nispasswd_authresult_u.npd_verf.npd_xid);
  IXDR_PUT_U_INT32 (ixdr, result.nispasswd_authresult_u.npd_verf.npd_xrandval);
  error = ecb_crypt ((char *) &CK, (char *) &cryptbuf, 8,
		     DES_DECRYPT | DES_HW);
  if (DES_FAILED (error))
    {
      fprintf (stderr, _("DES decryption failure!\n"));
      return -1;
    }

  /* fill out update request */
  memset (&update, 0, sizeof (update));
  update.ident = ntohl (cryptbuf.key.high);
  update.xnewpass.npd_xrandval = cryptbuf.key.low;
  memset (update.xnewpass.pass, '\0', __NPD_MAXPASSBYTES);
  strncpy (update.xnewpass.pass, data->oldclearpwd,
	   __NPD_MAXPASSBYTES);

  if (data->new_gecos)
    update.pass_info.pw_gecos = strdup (data->new_gecos);
  else
    update.pass_info.pw_gecos = "";

  if (data->new_shell)
    update.pass_info.pw_shell = strdup (data->new_shell);
  else
    update.pass_info.pw_shell = "";

  memset (ivec, 0, 8);
  error = cbc_crypt ((char *) &CK, (char *) &update.xnewpass,
		     16, DES_ENCRYPT | DES_HW, ivec);
  if (DES_FAILED (error))
    {
      fprintf (stderr, _("DES decryption failure!\n"));
      return -1;
    }

  /* update.xnewpass.npd_xrandval will be changed in XDR again */
  update.xnewpass.npd_xrandval = ntohl (update.xnewpass.npd_xrandval);

  memset ((char *) &updresult, 0, sizeof (updresult));
  timeout.tv_sec = 25;
  timeout.tv_usec = 0;
  error = clnt_call (clnt, NISPASSWD_UPDATE, (xdrproc_t) __pam_xdr_npd_update,
		     (caddr_t) &update,
		     (xdrproc_t) __pam_xdr_nispasswd_updresult,
		     (caddr_t) &updresult, timeout);
  if (error)
    {
      clnt_perrno (error);
      fprintf (stderr, "\n");
      return -1;
    }
  clnt_destroy (clnt);
  if (updresult.status != NPD_SUCCESS)
    {
      if (updresult.status == NPD_FAILED)
	{
	  fprintf (stderr, _("ERROR: %s\n       password not changed\n"),
		   npderr2str (updresult.nispasswd_updresult_u.npd_err));
	}
      else if (updresult.status == NPD_PARTIALSUCCESS)
	{
	  nispasswd_error *err;
	  fputs ("ERROR: Only partial success\n", stderr);
	  err = &updresult.nispasswd_updresult_u.reason;
	  while (err != NULL)
	    {
	      switch (err->npd_field)
		{
		case NPD_PASSWD:
		  fprintf (stderr, "\tpassword field: %s\n",
			   npderr2str (err->npd_code));
		  break;
		case NPD_GECOS:
		  fprintf (stderr, "\tgecos field: %s\n",
			   npderr2str (err->npd_code));
		case NPD_SHELL:
		  fprintf (stderr, "\tshell field: %s\n",
			   npderr2str (err->npd_code));
		  break;
		case NPD_SECRETKEY:
		  fprintf (stderr, "\tsecret key: %s\n",
			   npderr2str (err->npd_code));
		  break;
		}
	      err = err->next;
	    }
	}
      else
	{
	  fprintf (stderr, _("ERROR: Unknown error, don't know what happened\n"));
	}
      return -1;
    }

  fprintf (stderr, _("NIS+ password information changed for %s\n"),
	   request.username);
  fprintf (stderr, _("NIS+ credential information changed for %s\n"),
	   request.username);

  nis_free_object (obj);
  return 0;
}


/* Update password in NIS+ passwd table, do not use rpc.nispasswdd */
static int
update_nisd (nis_object *obj, user_t *data)
{
  char buf[strlen (obj->zo_name) + strlen (obj->zo_domain) + 10];
  nis_result *result;

  if (data->new_gecos)
    {
      free (NISENTRYVAL(4,obj));
      NISENTRYVAL(4,obj) = strdup (data->new_gecos);
      NISENTRYFLAG(4,obj) = NISENTRYFLAG(4,obj) | EN_MODIFIED;
      NISENTRYLEN(4,obj) = strlen (NISENTRYVAL(4,obj));
    }

  if (data->new_shell)
    {
      free (NISENTRYVAL(6,obj));

      NISENTRYVAL(6,obj) = strdup (data->new_shell);
      NISENTRYFLAG(6,obj) = NISENTRYFLAG(6,obj) | EN_MODIFIED;
      NISENTRYLEN(6,obj) = strlen (NISENTRYVAL(6,obj));
    }

  sprintf (buf, "%s.%s", obj->zo_name, obj->zo_domain);
  result = nis_modify_entry (buf, obj, 0);
  if (result->status != NIS_SUCCESS)
    {
      fprintf (stderr, "nispasswd: Password information update failed\n");
      fprintf (stderr, "           %s\n", nis_sperrno (result->status));
      nis_freeresult (result);
      return 1;
    }
  else
    nis_freeresult (result);

  nis_free_object (obj);
  return 0;
}

int
npd_upd_pwd (const char *domainname, user_t *data)
{
  nis_result *result;
  nis_object *obj;
  char domain[NIS_MAXNAMELEN + 1];
  char *buf = NULL;
  char *group;

  if (strlen (domainname) == 0)
    strncpy (domain, nis_local_directory (), NIS_MAXNAMELEN);
  else
    strncpy (domain, domainname, NIS_MAXNAMELEN);
  domain[NIS_MAXNAMELEN] = '\0';

  /* Get group of passwd table */
  buf = alloca (strlen (data->pw.pw_name) + strlen (domain) + 30);
  sprintf (buf, "passwd.org_dir.%s", domain);
  result = nis_lookup (buf, 0);
  if (result->status != NIS_SUCCESS)
    {
      fprintf (stderr, _("NIS+ passwd table not found: %s\n"),
	       nis_sperrno (result->status));
      return -1;
    }

  group = alloca (strlen (NIS_RES_OBJECT(result)->zo_group) + 1);
  strcpy (group, NIS_RES_OBJECT(result)->zo_group);
  nis_freeresult (result);

  /* Get old NIS+ passwd information for caller or parameter. */
  sprintf (buf, "[name=%s],passwd.org_dir.%s", data->pw.pw_name, domain);

  result = nis_list (buf, 0, NULL, NULL);

  if (result->status != NIS_SUCCESS)
    {
      fprintf (stderr, _("User not found in NIS+ table.\n"));
      return -1;
    }

  obj = nis_clone_object (result->objects.objects_val, NULL);
  nis_freeresult (result);

  if (nis_ismember (nis_local_principal (), group))
    return update_nisd (obj, data);
  else
    return update_npd (obj, data);
}
