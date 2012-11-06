
#ifndef _LIBLDAP_H_
#define _LIBLDAP_H_ 1

#ifdef USE_LDAP

#include <grp.h>
#include <pwd.h>
#include <shadow.h>

/* /etc/ldap.conf nss_ldap-style configuration */
typedef struct ldap_config
  {
    /* URI */
    char *uri;
    /* space delimited list of servers */
    char *host;
    /* port, expected to be common to all servers */
    int port;
    /* base DN, eg. dc=gnu,dc=org */
    char *base;
    /* scope for searches */
    int scope;
    /* deref policy */
    int deref;
    /* bind dn/pw for "anonymous" authentication */
    char *binddn;
    char *bindpw;
    /* bind dn/pw for "root" authentication */
    char *rootbinddn;
    char *rootbindpw;
    /* SSL config states */
#define SSL_OFF          0
#define SSL_LDAPS        1
#define SSL_START_TLS    2
    int ssl_on;
    /* SSL path */
    char *sslpath;
    /* attribute to set PAM_USER based on */
    char *tmplattr;
    /* default template user */
    char *tmpluser;
    /* search for Netscape password policy */
    int getpolicy;
    /* host attribute checking, for access authorization */
    int checkhostattr;
    /* group name; optional, for access authorization */
    char *groupdn;
    /* group membership attribute; defaults to uniquemember */
    char *groupattr;
    /* LDAP protocol version */
    int version;
    /* search timelimit */
    int timelimit;
    /* bind timelimit */
    int bind_timelimit;
    /* automatically chase referrals */
    int referrals;
    /* restart interrupted syscalls, OpenLDAP only */
    int restart;
    /* chauthtok config states */
#define PASSWORD_CLEAR   0
#define PASSWORD_CRYPT   1
#define PASSWORD_MD5     2
#define PASSWORD_NDS     3
#define PASSWORD_AD      4
#define PASSWORD_EXOP    5
    int password_type;
    /* tls check peer */
    int tls_checkpeer;
    /* tls ca certificate file */
    char *tls_cacertfile;
    /* tls ca certificate dir */
    char *tls_cacertdir;
    /* tls ciphersuite */
    char *tls_ciphers;
    /* tls certificate */
    char *tls_cert;
    /* tls key */
    char *tls_key;
    /* use the RFC2307bis Schema (groupmembers with full DN) */
    int use_rfc2307bis;
  }
ldap_config_t;

/* Password controls sent to client */
#ifndef LDAP_CONTROL_PWEXPIRED
#define LDAP_CONTROL_PWEXPIRED      "2.16.840.1.113730.3.4.4"
#endif /* LDAP_CONTROL_PWEXPIRED */
#ifndef LDAP_CONTROL_PWEXPIRING
#define LDAP_CONTROL_PWEXPIRING     "2.16.840.1.113730.3.4.5"
#endif /* LDAP_CONTROL_PWEXPIRING */

#ifndef LDAP_OPT_ON
#define LDAP_OPT_ON ((void *) 1)
#endif /* LDPA_OPT_ON */
#ifndef LDAP_OPT_OFF
#define LDAP_OPT_OFF ((void *) 0)
#endif /* LDAP_OPT_OFF */

/* Seconds in a day */
#define SECSPERDAY 86400

/* Netscape per-use password attributes. Unused except for DN. */
typedef struct bind_info {
  /* user name, to validate info cache */
  char *user;
  /* DN to use for binding */
  char *dn;
  /* temporary cache of user's bind credentials for rebind function */
  char *pw;
  /* bound as user DN */
  int bound_as_user;
} bind_info_t;

/*
 * Per PAM-call LDAP session. We keep the user info and
 * LDAP handle cached to minimize binds and searches to
 * the directory, particularly as you can't rebind within
 * a V2 session.
 */
#if defined(_INCLUDED_FROM_LIBLDAP_C_)
typedef struct ldap_session
  {
    LDAP *ld;
    ldap_config_t *conf;
    bind_info_t *bind;
  }
ldap_session_t;
#else
typedef struct ldap_session_t ldap_session_t;
#endif

void free_ldap_config (ldap_config_t **pconfig);
ldap_session_t *create_ldap_session (const char *configFile);
int open_ldap_session (ldap_session_t *);
int close_ldap_session (ldap_session_t *);

int ldap_authentication (ldap_session_t *session, const char *user,
			 const char *binddn, const char *bindpw);
int ldap_update_user (ldap_session_t *session, const char *user,
		      const char *binddn, const char *password,
		      const char *field, const char *new_value);
int ldap_delete_user (ldap_session_t *session, const char *user,
		      const char *binddn, const char *password);
int ldap_update_group (ldap_session_t *session, const char *group,
		       const char *binddn, const char *password,
		       int op, const char *field, const char *new_value);
int ldap_add_groupmember (ldap_session_t *session, const char* group,
		          const char *binddn, const char *password,
		          const char *member, int first );
int ldap_del_groupmember (ldap_session_t *session, const char* group,
		          const char *binddn, const char *password,
		          const char *member, int last );
int ldap_delete_group (ldap_session_t *session, const char *group,
		       const char *binddn, const char *password);
int ldap_create_user (ldap_session_t *session, struct passwd *pw,
		      struct spwd *sp, const char *binddn,
		      const char *password);
int ldap_create_group (ldap_session_t *session, struct group *gr,
		       const char *binddn, const char *password);
char *convert_user_to_dn (ldap_session_t *session, const char *user);
char *ldap_find_user_baseou (ldap_session_t *session);
char *ldap_find_group_baseou (ldap_session_t *session);

char *get_ldap_password (const char *binddn);
char *get_caller_dn (void);

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

#endif /* USE_LDAP */
#endif /* _LIBLDAP_H_ */
