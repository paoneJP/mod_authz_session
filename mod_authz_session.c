/* 
** mod_authz_session:
**   access control using session values stored in mod_session.
**
** @author Takashi Yahata (@paoneJP)
** @copyright Copyright (c) 2014, Takashi Yahata
** @license MIT License
**
*/ 

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>

#include <mod_session.h>


#define NG !OK
#define LOG_PREFIX "mod_authz_session: "


typedef struct {
    int authoritative ;
    const char *auth_url ;
    apr_array_header_t *requires ;
} config_rec ;


typedef struct {
    const char *key ;
    const char *val ;
} require_rec ;


module AP_MODULE_DECLARE_DATA authz_session_module ;

apr_OFN_ap_session_load_t *ap_session_load = NULL ;
apr_OFN_ap_session_get_t *ap_session_get = NULL ;
apr_OFN_ap_session_set_t *ap_session_set = NULL ;


static void *create_dir_config(apr_pool_t *p, char *dir)
{
    config_rec *cfg ;

    cfg = (config_rec *)apr_pcalloc(p, sizeof(config_rec)) ;
    cfg->authoritative = 1 ;
    cfg->auth_url = NULL ;
    cfg->requires = apr_array_make(p, 0, sizeof(require_rec)) ;
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


static int post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp,
                       server_rec *s)
{
    if (!ap_session_load || !ap_session_get || !ap_session_set) {
        ap_session_load = APR_RETRIEVE_OPTIONAL_FN(ap_session_load) ;
        ap_session_get = APR_RETRIEVE_OPTIONAL_FN(ap_session_get) ;
        ap_session_set = APR_RETRIEVE_OPTIONAL_FN(ap_session_set) ;
        if (!ap_session_load || !ap_session_get || !ap_session_set) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, LOG_PREFIX
                         "You must load mod_session to enable the "
                         "mod_authz_session functions") ;
            return NG ;
        }
    }
    return OK ;
}


static int access_checker(request_rec *r)
{
    config_rec *cfg ;
    session_rec *z ;
    apr_status_t rv ;
    apr_table_t *t ;
    require_rec req ;
    register int i ;
    const char *v ;
    const apr_array_header_t *a ;
    apr_table_entry_t e ;

    cfg = ap_get_module_config(r->per_dir_config, &authz_session_module) ;
    if (!cfg->authoritative) {
        return DECLINED ;
    }

    rv = ap_session_load(r, &z) ;
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, LOG_PREFIX
                     "ap_session_load() failed.") ;
        return NG ;
    }

    t = apr_table_make(r->pool, 0) ;
    for (i = 0; i < cfg->requires->nelts; i++) {
        req = APR_ARRAY_IDX(cfg->requires, i, require_rec) ;
        v = apr_table_get(t, req.key) ;
        if (!v) {
            apr_table_set(t, req.key, "NG") ;
        } else if (strcmp(v, "OK") == 0) {
            continue ;
        }
        ap_session_get(r, z, req.key, &v) ;
        if (v) {
            if (strcmp(v, req.val) == 0 ||
                    strcmp(req.val, "_has_value") == 0) {
                apr_table_set(t, req.key, "OK") ;
            }
        }
    }

    a = apr_table_elts(t) ;
    for (i = 0; i < a->nelts; i++) {
        e = APR_ARRAY_IDX(a, i, apr_table_entry_t) ;
        if (strcmp(e.val, "OK") != 0) {
            if (cfg->auth_url) {
                apr_table_set(r->headers_out, "Location", cfg->auth_url) ;
                return HTTP_MOVED_TEMPORARILY ;
            }
            return HTTP_UNAUTHORIZED ;
        }
    }
    return DECLINED ;
}


static const command_rec cmds[] =
{
    AP_INIT_FLAG("AuthzSessionAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(config_rec, authoritative), OR_AUTHCFG,
                 "Set to 'On' to enable access control using session values "
                 "stored in mod_session. (default: Off)."),
    AP_INIT_TAKE1("AuthzSessionAuthURL", ap_set_string_slot,
                 (void *)APR_OFFSETOF(config_rec, auth_url), OR_AUTHCFG,
                 "URL of authentication (session setter) application."),
    AP_INIT_ITERATE2("AuthzSessionRequire", handle_AuthzSessionRequire,
                 NULL, OR_AUTHCFG,
                 "Conditions for permit access. Specify key of session data, "
                 "followed by value(s)."),
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
