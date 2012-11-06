#ifndef _NISPASSWD_H_
#define _NISPASSWD_H_

#include <rpc/rpc.h>

enum nispasswd_status {
  NPD_SUCCESS = 0,
  NPD_TRYAGAIN = 1,
  NPD_PARTIALSUCCESS = 2,
  NPD_FAILED = 3,
};
typedef enum nispasswd_status nispasswd_status;

enum nispasswd_code {
  NPD_NOTMASTER = 0,
  NPD_NOSUCHENTRY = 1,
  NPD_IDENTINVALID = 2,
  NPD_NOPASSWD = 3,
  NPD_NOSHDWINFO = 4,
  NPD_SHDWCORRUPT = 5,
  NPD_NOTAGED = 6,
  NPD_CKGENFAILED = 7,
  NPD_VERFINVALID = 8,
  NPD_PASSINVALID = 9,
  NPD_ENCRYPTFAIL = 10,
  NPD_DECRYPTFAIL = 11,
  NPD_KEYSUPDATED = 12,
  NPD_KEYNOTREENC = 13,
  NPD_PERMDENIED = 14,
  NPD_SRVNOTRESP = 15,
  NPD_NISERROR = 16,
  NPD_SYSTEMERR = 17,
  NPD_BUFTOOSMALL = 18,
  NPD_INVALIDARGS = 19,
};
typedef enum nispasswd_code nispasswd_code;

enum nispasswd_field {
  NPD_PASSWD = 0,
  NPD_GECOS = 1,
  NPD_SHELL = 2,
  NPD_SECRETKEY = 3,
};
typedef enum nispasswd_field nispasswd_field;

struct nispasswd_error {
  nispasswd_field npd_field;
  nispasswd_code npd_code;
  struct nispasswd_error *next;
};
typedef struct nispasswd_error nispasswd_error;

struct passwd_info {
  char *pw_gecos;
  char *pw_shell;
};
typedef struct passwd_info passwd_info;

struct npd_request {
  char *username;
  char *domain;
  char *key_type;
  struct {
    u_int user_pub_key_len;
    u_char *user_pub_key_val;
  } user_pub_key;
  struct {
    u_int npd_authpass_len;
    u_char *npd_authpass_val;
  } npd_authpass;
  u_int ident;
};
typedef struct npd_request npd_request;
#define __NPD_MAXPASSBYTES 12

typedef char passbuf[__NPD_MAXPASSBYTES];

struct npd_newpass {
  u_int npd_xrandval;
  passbuf pass;
};
typedef struct npd_newpass npd_newpass;

struct npd_update {
  u_int ident;
  npd_newpass xnewpass;
  passwd_info pass_info;
};
typedef struct npd_update npd_update;

struct nispasswd_verf {
  u_int npd_xid;
  u_int npd_xrandval;
};
typedef struct nispasswd_verf nispasswd_verf;

struct nispasswd_authresult {
  nispasswd_status status;
  union {
    nispasswd_verf npd_verf;
    nispasswd_code npd_err;
  } nispasswd_authresult_u;
};
typedef struct nispasswd_authresult nispasswd_authresult;

struct nispasswd_updresult {
  nispasswd_status status;
  union {
    nispasswd_error reason;
    nispasswd_code npd_err;
  } nispasswd_updresult_u;
};
typedef struct nispasswd_updresult nispasswd_updresult;

#define NISPASSWD_PROG 100303
#define NISPASSWD_VERS 1

#define NISPASSWD_AUTHENTICATE 1
extern  bool_t nispasswd_authenticate_1_svc(npd_request *, nispasswd_authresult *, struct svc_req *);
#define NISPASSWD_UPDATE 2
extern  bool_t nispasswd_update_1_svc(npd_update *, nispasswd_updresult *, struct svc_req *);
extern int nispasswd_prog_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

#endif /* !_NISPASSWD_H_ */
