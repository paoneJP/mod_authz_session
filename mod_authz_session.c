/* 
** mod_authz_session:
**   access control using session values stored in mod_session.
**
** @author Takashi Yahata (@paoneJP)
** @copyright Copyright (c) 2014-2015, Takashi Yahata
** @license MIT License
**
*/ 

#include <string.h>
#include <ctype.h>
#include <time.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <apr_strings.h>
#include <apr_uri.h>

#include <mod_session.h>
#include <mod_ssl.h>


#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(authz_session) ;
#endif
module AP_MODULE_DECLARE_DATA authz_session_module ;


/* for compatibility with apache2.2.       */
/* works with mod_session-apache2.2-ports. */
#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER < 4
AP_DECLARE(char *) ap_escape_urlencoded(apr_pool_t *p, const char *s) ;
#endif


#define NG !OK


typedef struct {
    int authoritative ;
    int auth_redirect ;
    const char *auth_url ;
    const char *target_url_key ;
    const char *target_url_use_prefix ;
    apr_array_header_t *requires ;
    apr_array_header_t *requires_time_is_before ;
    apr_array_header_t *requires_time_is_after ;
    int require_time_allowance ;
} config_rec ;


typedef struct {
    const char *key ;
    const char *val ;
} require_rec ;


module AP_MODULE_DECLARE_DATA authz_session_module ;

apr_OFN_ap_session_load_t *ap_session_load = NULL ;
apr_OFN_ap_session_get_t *ap_session_get = NULL ;
apr_OFN_ap_session_set_t *ap_session_set = NULL ;

apr_OFN_ssl_is_https_t *ssl_is_https = NULL ;


static void *create_dir_config(apr_pool_t *p, char *dir)
{
    config_rec *cfg ;

    cfg = (config_rec *)apr_pcalloc(p, sizeof(config_rec)) ;
    cfg->requires = apr_array_make(p, 0, sizeof(require_rec)) ;
    cfg->requires_time_is_before = apr_array_make(p, 0, sizeof(const char*)) ;
    cfg->requires_time_is_after = apr_array_make(p, 0, sizeof(const char*)) ;
    return (void *)cfg ;
}


static const char *handle_AuthzSessionRequire(cmd_parms *cmd, void *mconfig,
                      const char *word1, const char *word2)
{
    config_rec *cfg ;
    require_rec *req ;

    cfg = (config_rec *)mconfig ;
    req = (require_rec *)apr_array_push(cfg->requires) ;
    req->key = word1 ;
    req->val = word2 ;
    return NULL ;
}


static const char *handle_AuthzSessionRequireTimeIsBefore(
    cmd_parms *cmd, void *mconfig, const char *word)
{
    config_rec *cfg ;
    const char **p ;

    cfg = (config_rec*)mconfig ;
    p = (const char **)apr_array_push(cfg->requires_time_is_before) ;
    *p = apr_pstrdup(cmd->pool, word) ;
    return NULL ;
}


static const char *handle_AuthzSessionRequireTimeIsAfter(
    cmd_parms *cmd, void *mconfig, const char *word)
{
    config_rec *cfg ;
    const char **p ;

    cfg = (config_rec*)mconfig ;
    p = (const char **)apr_array_push(cfg->requires_time_is_after) ;
    *p = apr_pstrdup(cmd->pool, word) ;
    return NULL ;
}


static int post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp,
                       server_rec *s)
{
    if (!ap_session_load || !ap_session_get || !ap_session_set) {
        ap_session_load = APR_RETRIEVE_OPTIONAL_FN(ap_session_load) ;
        ap_session_get = APR_RETRIEVE_OPTIONAL_FN(ap_session_get) ;
        ap_session_set = APR_RETRIEVE_OPTIONAL_FN(ap_session_set) ;
        if (!ap_session_load || !ap_session_get || !ap_session_set) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                         "You must load mod_session to enable the "
                         "mod_authz_session functions") ;
            return NG ;
        }
    }
    ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https) ;
    return OK ;
}


static const char *get_url(request_rec *r)
{
    config_rec *cfg ;
    const char *v ;
    const char *h ;
    const char *u1, *u2 ;
    const char *rv ;
    char *p ;
    int is_https ;

    cfg = ap_get_module_config(r->per_dir_config, &authz_session_module) ;

    is_https = 0 ;
    if (ssl_is_https && ssl_is_https(r->connection)) {
        is_https = 1 ;
    }
    if ((v = apr_table_get(r->headers_in, "X-Forwarded-Proto")) &&
            strcasecmp("https", v) == 0) {
        is_https = 1 ;
    }

    h = r->hostname ;
    if ((v = apr_table_get(r->headers_in, "X-Forwarded-Host"))) {
        h = apr_pstrdup(r->pool, v) ;
        if ((p = strchr(h, ','))) {
            *p = '\0' ;
        }
    }

    if (cfg->target_url_use_prefix) {
        u1 = cfg->target_url_use_prefix ;
    } else {
        u1 = apr_pstrcat(r->pool,
                         is_https ? "https://" : "http://",
                         h,
                         NULL) ;
    }

    u2 = NULL ;
    if (r->args) {
        u2 = apr_pstrcat(r->pool, "?", r->args, NULL) ;
    }

    rv = apr_pstrcat(r->pool, u1, r->uri, u2, NULL) ;
    return rv ;
}


static time_t get_time(const char *s)
{
    const char *p ;
    time_t rv ;

    for (p = s; *p != '\0'; p++) {
        if (!isdigit(*p)) {
            return -1 ;
        }
    }
    rv = apr_atoi64(s) ;
    return rv ;
}


static int access_checker(request_rec *r)
{
    config_rec *cfg ;
    session_rec *z ;
    apr_status_t rv ;
    apr_table_t *t ;
    require_rec req ;
    register int i ;
    const char *v, *k, *u1 ;
    const apr_array_header_t *a ;
    apr_table_entry_t e ;
    time_t tc, tv ;

    cfg = ap_get_module_config(r->per_dir_config, &authz_session_module) ;
    if (!cfg->authoritative) {
        return DECLINED ;
    }

    rv = ap_session_load(r, &z) ;
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "ap_session_load() failed.") ;
        return NG ;
    }

    t = apr_table_make(r->pool, 0) ;
    for (i = 0; i < cfg->requires->nelts; i++) {
        req = APR_ARRAY_IDX(cfg->requires, i, require_rec) ;
        v = apr_table_get(t, req.key) ;
        if (!v) {
            apr_table_set(t, req.key, "0") ;
        } else if (v[0] == '1') {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "already satisfied: key=%s, require=%s",
                          req.key, req.val) ;
            continue ;
        }
        ap_session_get(r, z, req.key, &v) ;
        if (v) {
            if (strcmp(v, req.val) == 0 ||
                    strcmp(req.val, "_has_value") == 0) {
                apr_table_set(t, req.key, "1") ;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "satisfied: key=%s, require=%s, value=%s",
                              req.key, req.val, v) ;
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "not satisfied: key=%s, require=%s, value=%s",
                              req.key, req.val, v) ;
            }
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "not satisfied: key=%s, require=%s, value not found",
                          req.key, req.val) ;
        }
    }

    a = apr_table_elts(t) ;
    for (i = 0; i < a->nelts; i++) {
        e = APR_ARRAY_IDX(a, i, apr_table_entry_t) ;
        if (e.val[0] == '0') {
            goto UNAUTHORIZED ;
        }
    }

    tc = time(NULL) ;
    for (i = 0; i < cfg->requires_time_is_before->nelts; i++) {
        k = APR_ARRAY_IDX(cfg->requires_time_is_before, i, const char *) ;
        ap_session_get(r, z, k, &v) ;
        if (!v) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "not satisfied: time %ld is before key=%s, "
                          "value not found", tc, k) ;
            goto UNAUTHORIZED ;
        }
        tv = get_time(v) ;
        if (tv < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "key %s is not a POSIX time value. value=%s",
                          k, v) ;
            goto UNAUTHORIZED ;
        }
        if (!(tc <= tv + cfg->require_time_allowance)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "not satisfied: time %ld is before key=%s, "
                          "value=%s, allowance=%d",
                          tc, k, v, cfg->require_time_allowance) ;
            goto UNAUTHORIZED ;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "satisfied: time %ld is before key=%s, value=%s, "
                      "allowance=%d",
                      tc, k, v, cfg->require_time_allowance) ;
    }
    for (i = 0; i < cfg->requires_time_is_after->nelts; i++) {
        k = APR_ARRAY_IDX(cfg->requires_time_is_after, i, const char *) ;
        ap_session_get(r, z, k, &v) ;
        if (!v) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "not satisfied: time %ld is after key=%s, "
                          "value not found", tc, k) ;
            goto UNAUTHORIZED ;
        }
        tv = get_time(v) ;
        if (tv < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "key %s is not a POSIX time value. value=%s",
                          k, v) ;
            goto UNAUTHORIZED ;
        }
        if (!(tv <= tc + cfg->require_time_allowance)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "not satisfied: time %ld is after key=%s, "
                          "value=%s, allowance=%d",
                          tc, k, v, cfg->require_time_allowance) ;
            goto UNAUTHORIZED ;
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "satisfied: time %ld is after key=%s, value=%s, "
                      "allowance=%d",
                      tc, k, v, cfg->require_time_allowance) ;
    }

    return DECLINED ;


  UNAUTHORIZED:

    if (cfg->auth_redirect) {
        if (!cfg->auth_url) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "AuthzSession is on but AuthzSessionAuthURL is "
                          "not specified") ;
            return NG ;
        }

        u1 = NULL ;
        if (cfg->target_url_key) {
            u1 = apr_pstrcat(r->pool,
                             strchr(cfg->auth_url, '?') ? "&" : "?",
                             ap_escape_urlencoded(r->pool,
                                                  cfg->target_url_key),
                             "=",
                             ap_escape_urlencoded(r->pool, get_url(r)),
                             NULL) ;
        }

        v = apr_pstrcat(r->pool, cfg->auth_url, u1, NULL) ;
        apr_table_set(r->headers_out, "Location", v) ;
        return HTTP_MOVED_TEMPORARILY ;
    }

    return HTTP_UNAUTHORIZED ;
}


static const command_rec cmds[] =
{
    AP_INIT_FLAG("AuthzSessionAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(config_rec, authoritative), OR_AUTHCFG,
                 "Set to 'On' to enable access control using session values "
                 "stored in mod_session."),
    AP_INIT_FLAG("AuthzSessionAuthRedirect", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(config_rec, auth_redirect), OR_AUTHCFG,
                 "Redirect to authentication page (session initiator page) "
                 "when client does not satisfy required condition."),
    AP_INIT_TAKE1("AuthzSessionAuthURL", ap_set_string_slot,
                  (void *)APR_OFFSETOF(config_rec, auth_url), OR_AUTHCFG,
                  "URL of authentication page (session initiator page)."),
    AP_INIT_TAKE1("AuthzSessionTargetURLKey", ap_set_string_slot,
                  (void *)APR_OFFSETOF(config_rec, target_url_key), OR_AUTHCFG,
                  "If this directive is specified, when redirecting to "
                  "authentication page (session initiator page) pass "
                  "the URL of requested page to specified key."),
    AP_INIT_TAKE1("AuthzSessionTargetURLUsePrefix", ap_set_string_slot,
                  (void *)APR_OFFSETOF(config_rec, target_url_use_prefix),
                  OR_AUTHCFG,
                  "Specify the URL prefix (scheme, hostname, port, path) of "
                  "requested page. If not specified, URL is automatically "
                  "guessed from request parameters."),
    AP_INIT_ITERATE2("AuthzSessionRequire", handle_AuthzSessionRequire,
                     NULL, OR_AUTHCFG,
                     "Conditions for permit access. Specify key of session "
                     "data, followed by value(s)."),
    AP_INIT_TAKE1("AuthzSessionRequireTimeIsBefore",
                  handle_AuthzSessionRequireTimeIsBefore, NULL, OR_AUTHCFG,
                  "Time condition for permit access. If specified key of "
                  "session data is POSIX time and if current time is before "
                  "the time, access is permitted."),
    AP_INIT_TAKE1("AuthzSessionRequireTimeIsAfter",
                  handle_AuthzSessionRequireTimeIsAfter, NULL, OR_AUTHCFG,
                  "Time condition for permit access. If specified key of "
                  "session data is POSIX time and if current time is after "
                  "the time, access is permitted."),
    AP_INIT_TAKE1("AuthzSessionRequireTimeAllowance", ap_set_int_slot,
                  (void *)APR_OFFSETOF(config_rec, require_time_allowance),
                  OR_AUTHCFG,
                  "Time allowance seconds used with "
                  "AuthzSessionRequireTimeIsBefore and "
                  "AuthzSessionTimeIsAfter directives."),
    { NULL }
} ;


static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE) ;
    ap_hook_access_checker(access_checker, NULL, NULL, APR_HOOK_MIDDLE) ;
}


module AP_MODULE_DECLARE_DATA authz_session_module = {
    STANDARD20_MODULE_STUFF, 
    create_dir_config,     /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    cmds,                  /* table of config file commands       */
    register_hooks         /* register hooks                      */
} ;
