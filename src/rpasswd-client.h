
#ifndef _RPASSWD_CLIENT_H
#define _RPASSWD_CLIENT_H  1

/* Version number of the daemon interface.  */
#define RPASSWD_VERSION 1

/* Default port number on which the server listens.  */
#define RPASSWDD_PORT 774

/* Path for the configuration file.  */
#define _PATH_RPASSWDCONF   "/etc/rpasswd.conf"

/* Available requests from client.  */
typedef enum
{
  START,                /* Normal user wishes to change password.  */
  START_ADMIN           /* Admin wishes to change the password for
			   another user.  */
} request_type;

/* Header for first requests.  */
typedef struct
{
  int32_t version;      /* Version number of the daemon interface.  */
  request_type request; /* Normal user or Admin account.  */
  int32_t locale_len;   /* Length of the locale string.  */
  int32_t data_len;     /* Length of following data.  */
} request_header;

/* Available responses from server.  */
typedef enum
{
  PROMPT_ECHO_OFF,
  PROMPT_ECHO_ON,
  ERROR_MSG,
  TEXT_INFO,
  FINISH
} response_type;

/* Header for all messages from server.  */
typedef struct
{
  response_type type;    /* Action requested.  */
  int32_t data_len;      /* Length of following data.  */
} response_header;

/* Header for answers from conversion function.  */
typedef struct
{
  u_int32_t retval;     /* Service requested.  */
  int32_t data_len;     /* Length of following data.  */
} conv_header;

#endif /* rpasswd client */
