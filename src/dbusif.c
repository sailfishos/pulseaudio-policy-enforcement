#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <pulsecore/dbus-shared.h>
#include <pulsecore/core-util.h>
#include <meego/shared-data.h>
#include <sailfishos/defines.h>

#include "userdata.h"
#include "dbusif.h"
#include "classify.h"
#include "context.h"
#include "policy-group.h"
#include "sink-ext.h"
#include "source-ext.h"
#include "card-ext.h"
#include "sink-input-ext.h"
#include "policy.h"

#define ADMIN_DBUS_MANAGER          "org.freedesktop.DBus"
#define ADMIN_DBUS_PATH             "/org/freedesktop/DBus"
#define ADMIN_DBUS_INTERFACE        "org.freedesktop.DBus"

#define ADMIN_NAME_OWNER_CHANGED    "NameOwnerChanged"
#define ADMIN_GET_NAME_OWNER        "GetNameOwner"

#define POLICY_DBUS_INTERFACE       "com.nokia.policy"
#define POLICY_DBUS_MYPATH          "/com/nokia/policy/enforce/pulseaudio"
#define POLICY_DBUS_MYNAME          "com.nokia.policy.pulseaudio"
#define POLICY_DBUS_PDPATH          "/com/nokia/policy"
#define POLICY_DBUS_PDNAME          "org.freedesktop.ohm"

#define POLICY_DECISION             "decision"
#define POLICY_STREAM_INFO          "stream_info"
#define POLICY_ACTIONS              "audio_actions"
#define POLICY_STATUS               "status"

#define PROP_ROUTE_SINK_TARGET      "policy.sink_route.target"
#define PROP_ROUTE_SINK_MODE        "policy.sink_route.mode"
#define PROP_ROUTE_SINK_HWID        "policy.sink_route.hwid"
#define PROP_ROUTE_SOURCE_TARGET    "policy.source_route.target"
#define PROP_ROUTE_SOURCE_MODE      "policy.source_route.mode"
#define PROP_ROUTE_SOURCE_HWID      "policy.source_route.hwid"

#define POLICY_DBUS_INFO            "info"
#define POLICY_DBUS_MEDIA           "media"
#define POLICY_DBUS_STATE_PATH      POLICY_DBUS_PDPATH "/" POLICY_DBUS_INFO
#define POLICY_DBUS_MEDIA_PATH      POLICY_DBUS_PDPATH "/" POLICY_DBUS_INFO
#define POLICY_DBUS_STATE_ACT       "active"
#define POLICY_DBUS_STATE_INACT     "inactive"

#define POLICY_DBUS_CARD            "card_info"
#define POLICY_DBUS_CARD_PATH       POLICY_DBUS_PDPATH "/" POLICY_DBUS_CARD
#define POLICY_DBUS_CARD_PROFILE    "profile_changed"


#define STRUCT_OFFSET(s,m) ((char *)&(((s *)0)->m) - (char *)0)

#define MAX_ROUTING_DECISIONS 2

struct routing_decision {      /* temporary storage for routing decision information */
    enum pa_policy_route_class class;
    char *target;
    char *mode;
    char *hwid;
};

struct pa_policy_dbusif {
    pa_dbus_connection *conn;
    DBusPendingCall    *pending_pdp_state;
    DBusPendingCall    *pending_pdp_registration;
    char               *ifnam;   /* signal interface */
    char               *mypath;  /* my signal path */
    char               *pdpath;  /* policy daemon's signal path */
    char               *pdnam;   /* policy daemon's D-Bus name */
    char               *admrule; /* match rule to catch name changes */
    char               *actrule; /* match rule to catch action signals */
    char               *strrule; /* match rule to catch stream info signals */
    bool                regist;  /* wheter or not registered to policy daemon*/
    bool                route_sources_first;
};

struct actdsc {                 /* action descriptor */
    const char         *name;
    int               (*parser)(struct userdata *u, DBusMessageIter *iter);
};

struct argdsc {                 /* argument descriptor for actions */
    const char         *name;
    int                 offs;
    int                 type;
};

struct argrt {                  /* audio_route arguments */
    char               *type;
    char               *device;
    char               *mode;
    char               *hwid;
};

struct argvol {                 /* volume_limit arguments */
    char               *group;
    int32_t             limit;
};

struct argcork {                /* audio_cork arguments */
    char               *group;
    char               *cork;
};

struct argmute {
    char               *device;
    char               *mute;
};

struct argctx {                 /* context arguments */
    char               *variable;
    char               *value;
};

static int action_parser(DBusMessageIter *, struct argdsc *, void *, int);
static int audio_route_parser(struct userdata *, DBusMessageIter *);
static int volume_limit_parser(struct userdata *, DBusMessageIter *);
static int audio_cork_parser(struct userdata *, DBusMessageIter *);
static int audio_mute_parser(struct userdata *, DBusMessageIter *);
static int context_parser(struct userdata *, DBusMessageIter *);

static DBusHandlerResult filter(DBusConnection *, DBusMessage *, void *);
static void handle_admin_message(struct userdata *, DBusMessage *);
static void handle_info_message(struct userdata *, DBusMessage *);
static void handle_action_message(struct userdata *, DBusMessage *);
static void getnameowner_cb(DBusPendingCall *, void *);
static void pdp_get_state(struct pa_policy_dbusif *, struct userdata *);
static void pdp_get_state_cancel(struct pa_policy_dbusif *);
static void registration_cb(DBusPendingCall *, void *);
static int  pdp_register_ep(struct pa_policy_dbusif *, struct userdata *);
static void pdp_register_ep_cancel(struct pa_policy_dbusif *);
static int  signal_status(struct userdata *, uint32_t, uint32_t);
static void pa_policy_free_dbusif(struct pa_policy_dbusif *,struct userdata *);



struct pa_policy_dbusif *pa_policy_dbusif_init(struct userdata *u,
                                               const char      *ifnam,
                                               const char      *mypath,
                                               const char      *pdpath,
                                               const char      *pdnam,
                                               bool             route_sources_first)
{
    pa_module               *m = u->module;
    struct pa_policy_dbusif *dbusif = NULL;
    DBusConnection          *dbusconn;
    DBusError                error;
    char                     actrule[512];
    char                     strrule[512];
    char                     admrule[512];

    dbusif = pa_xnew0(struct pa_policy_dbusif, 1);

    dbusif->route_sources_first = route_sources_first;

    dbus_error_init(&error);
    dbusif->conn = pa_dbus_bus_get(m->core, DBUS_BUS_SYSTEM, &error);

    if (dbusif->conn == NULL || dbus_error_is_set(&error)) {
        pa_log("failed to get SYSTEM Bus: %s: %s", error.name, error.message);
        goto fail;
    }

    dbusconn = pa_dbus_connection_get(dbusif->conn);

#if 0
    flags  = DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE;
    result = dbus_bus_request_name(dbusconn, POLICY_DBUS_MYNAME, flags,&error);

    if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER &&
        result != DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER    ) {
        pa_log("D-Bus name request failed: %s: %s", error.name, error.message);
        goto fail;
    }
#endif
 
    if (!dbus_connection_add_filter(dbusconn, filter,u, NULL)) {
        pa_log("failed to add filter function");
        goto fail;
    }

    if (!ifnam)
        ifnam = POLICY_DBUS_INTERFACE;

    if (!mypath)
        mypath = POLICY_DBUS_MYPATH;

    if (!pdpath)
        pdpath = POLICY_DBUS_PDPATH;

    if (!pdnam)
        pdnam = POLICY_DBUS_PDNAME;

    snprintf(admrule, sizeof(admrule), "type='signal',sender='%s',path='%s',"
             "interface='%s',member='%s',arg0='%s'", ADMIN_DBUS_MANAGER,
             ADMIN_DBUS_PATH, ADMIN_DBUS_INTERFACE, ADMIN_NAME_OWNER_CHANGED,
             pdnam);
    dbus_bus_add_match(dbusconn, admrule, &error);

    if (dbus_error_is_set(&error)) {
        pa_log("unable to subscribe name change signals on %s: %s: %s",
               ADMIN_DBUS_INTERFACE, error.name, error.message);
        goto fail;
    }

    snprintf(actrule, sizeof(actrule), "type='signal',interface='%s',"
             "member='%s',path='%s/%s'", ifnam, POLICY_ACTIONS,
             pdpath, POLICY_DECISION);
    dbus_bus_add_match(dbusconn, actrule, &error);

    if (dbus_error_is_set(&error)) {
        pa_log("unable to subscribe policy %s signal on %s: %s: %s",
               POLICY_ACTIONS, ifnam, error.name, error.message);
        goto fail;
    }

    snprintf(strrule, sizeof(strrule), "type='signal',interface='%s',"
             "member='%s',path='%s/%s'", ifnam, POLICY_STREAM_INFO,
             pdpath, POLICY_DECISION);
    dbus_bus_add_match(dbusconn, strrule, &error);

    if (dbus_error_is_set(&error)) {
        pa_log("unable to subscribe policy %s signal on %s: %s: %s",
               POLICY_STREAM_INFO, ifnam, error.name, error.message);
        goto fail;
    }

    pa_log_info("subscribed policy signals on %s", ifnam);

    dbusif->ifnam   = pa_xstrdup(ifnam);
    dbusif->mypath  = pa_xstrdup(mypath);
    dbusif->pdpath  = pa_xstrdup(pdpath);
    dbusif->pdnam   = pa_xstrdup(pdnam);
    dbusif->admrule = pa_xstrdup(admrule);
    dbusif->actrule = pa_xstrdup(actrule);
    dbusif->strrule = pa_xstrdup(strrule);

    pdp_get_state(dbusif, u);

    return dbusif;

 fail:
    pa_policy_free_dbusif(dbusif, u);
    dbus_error_free(&error);
    return NULL;
}

static void pa_policy_free_dbusif(struct pa_policy_dbusif *dbusif,
                                  struct userdata *u)
{
    DBusConnection          *dbusconn;

    if (!dbusif)
        return;

    pdp_get_state_cancel(dbusif);
    pdp_register_ep_cancel(dbusif);

    if (dbusif->conn) {
        dbusconn = pa_dbus_connection_get(dbusif->conn);

        if (u)
            dbus_connection_remove_filter(dbusconn, filter, u);

        dbus_bus_remove_match(dbusconn, dbusif->admrule, NULL);
        dbus_bus_remove_match(dbusconn, dbusif->actrule, NULL);
        dbus_bus_remove_match(dbusconn, dbusif->strrule, NULL);

        pa_dbus_connection_unref(dbusif->conn);
    }

    pa_xfree(dbusif->ifnam);
    pa_xfree(dbusif->mypath);
    pa_xfree(dbusif->pdpath);
    pa_xfree(dbusif->pdnam);
    pa_xfree(dbusif->admrule);
    pa_xfree(dbusif->actrule);
    pa_xfree(dbusif->strrule);
    pa_xfree(dbusif);
}

void pa_policy_dbusif_done(struct userdata *u)
{
    if (u) {
        pa_policy_free_dbusif(u->dbusif, u);
    }
}

void pa_policy_dbusif_send_device_state(struct userdata *u, const char *state,
                                        const struct pa_classify_result *list)
{
    const char              *path = POLICY_DBUS_STATE_PATH;

    struct pa_policy_dbusif *dbusif = u->dbusif;
    DBusConnection          *conn   = pa_dbus_connection_get(dbusif->conn);
    DBusMessage             *msg;
    DBusMessageIter          mit;
    DBusMessageIter          dit;
    uint32_t                 i;
    int                      sts;

    if (!dbusif->regist)
        return;

    if (!list || list->count == 0)
        return;

    msg = dbus_message_new_signal(path, dbusif->ifnam, POLICY_DBUS_INFO);

    if (msg == NULL) {
        pa_log("failed to make new info message");
        goto fail;
    }

    dbus_message_iter_init_append(msg, &mit);

    if (!dbus_message_iter_append_basic(&mit, DBUS_TYPE_STRING, &state) ||
        !dbus_message_iter_open_container(&mit, DBUS_TYPE_ARRAY,"s", &dit)){
        pa_log("failed to build info message");
        goto fail;
    }

    for (i = 0; i < list->count; i++) {
        if (!dbus_message_iter_append_basic(&dit, DBUS_TYPE_STRING, &list->types[i])) {
            pa_log("failed to build info message");
            goto fail;
        }
    }

    dbus_message_iter_close_container(&mit, &dit);

    sts = dbus_connection_send(conn, msg, NULL);

    if (!sts) {
        pa_log("Can't send info message: out of memory");
    }

 fail:
    if (msg)
        dbus_message_unref(msg);
}

void pa_policy_dbusif_send_card_profile_changed(struct userdata *u, const struct pa_classify_result *list,
                                                const char *profile)
{
    const char              *path = POLICY_DBUS_CARD_PATH;

    struct pa_policy_dbusif *dbusif = u->dbusif;
    DBusConnection          *conn   = pa_dbus_connection_get(dbusif->conn);
    const char              *event  = POLICY_DBUS_CARD_PROFILE;
    DBusMessage             *msg    = NULL;
    DBusMessageIter          mit;
    DBusMessageIter          dit;
    uint32_t                 i;
    int                      sts;

    if (!dbusif->regist)
        return;

    if (!list || list->count == 0)
        return;

    if (!profile)
        return;

    msg = dbus_message_new_signal(path, dbusif->ifnam, POLICY_DBUS_CARD);

    if (msg == NULL) {
        pa_log("failed to create new " POLICY_DBUS_CARD " signal");
        goto done;
    }

    dbus_message_iter_init_append(msg, &mit);

    if (!dbus_message_iter_append_basic(&mit, DBUS_TYPE_STRING, &event) ||
        !dbus_message_iter_append_basic(&mit, DBUS_TYPE_STRING, &profile) ||
        !dbus_message_iter_open_container(&mit, DBUS_TYPE_ARRAY,"s", &dit)) {
        pa_log("failed to build " POLICY_DBUS_CARD "/" POLICY_DBUS_CARD_PROFILE " signal");
        goto done;
    }

    for (i = 0; i < list->count; i++) {
        if (!dbus_message_iter_append_basic(&dit, DBUS_TYPE_STRING, &list->types[i])) {
            pa_log("failed to build " POLICY_DBUS_CARD "/" POLICY_DBUS_CARD_PROFILE " message");
            goto done;
        }
    }

    dbus_message_iter_close_container(&mit, &dit);

    sts = dbus_connection_send(conn, msg, NULL);

    if (!sts)
        pa_log("Can't send " POLICY_DBUS_CARD " message: out of memory");

 done:
    if (msg)
        dbus_message_unref(msg);
}

void pa_policy_dbusif_send_media_status(struct userdata *u, const char *media,
                                        const char *group, int active)
{
    const char              *path = POLICY_DBUS_MEDIA_PATH;
    const char              *type = POLICY_DBUS_MEDIA;

    struct pa_policy_dbusif *dbusif = u->dbusif;
    DBusConnection          *conn   = pa_dbus_connection_get(dbusif->conn);
    DBusMessage             *msg;
    const char              *state;
    int                      success;

    msg = dbus_message_new_signal(path, dbusif->ifnam, POLICY_DBUS_INFO);

    if (msg == NULL)
        pa_log("failed to make new info message");
    else {
        state = active ? POLICY_DBUS_STATE_ACT : POLICY_DBUS_STATE_INACT;

        success = dbus_message_append_args(msg,
                                           DBUS_TYPE_STRING, &type,
                                           DBUS_TYPE_STRING, &media,
                                           DBUS_TYPE_STRING, &group,
                                           DBUS_TYPE_STRING, &state,
                                           DBUS_TYPE_INVALID);
        
        if (!success)
            pa_log("Can't build D-Bus info message");
        else {
            if (!dbus_connection_send(conn, msg, NULL)) {
                pa_log("Can't send info message: out of memory");
            }
        }

        dbus_message_unref(msg);
    }
}

static DBusHandlerResult filter(DBusConnection *conn, DBusMessage *msg,
                                void *arg)
{
    struct userdata  *u = arg;

    if (dbus_message_is_signal(msg, ADMIN_DBUS_INTERFACE,
                               ADMIN_NAME_OWNER_CHANGED))
    {
        handle_admin_message(u, msg);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }


    if (dbus_message_is_signal(msg, POLICY_DBUS_INTERFACE,POLICY_STREAM_INFO)){
        handle_info_message(u, msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    if (dbus_message_is_signal(msg, POLICY_DBUS_INTERFACE, POLICY_ACTIONS)) {
        handle_action_message(u, msg);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void handle_admin_message(struct userdata *u, DBusMessage *msg)
{
    struct pa_policy_dbusif *dbusif;
    char                    *name;
    char                    *before;
    char                    *after;
    int                      success;

    pa_assert(u);
    pa_assert_se((dbusif = u->dbusif));

    success = dbus_message_get_args(msg, NULL,
                                    DBUS_TYPE_STRING, &name,
                                    DBUS_TYPE_STRING, &before,
                                    DBUS_TYPE_STRING, &after,
                                    DBUS_TYPE_INVALID);

    if (!success || !name) {
        pa_log("Received malformed '%s' message", ADMIN_NAME_OWNER_CHANGED);
        return;
    }

    if (strcmp(name, dbusif->pdnam)) {
        return;
    }

    if (after && *after) {
        pa_log_debug("policy decision point is up");
        pdp_get_state_cancel(dbusif);
        pdp_register_ep_cancel(dbusif);

        if (!dbusif->regist)
            pdp_register_ep(dbusif, u);
    }

    if (name && before && (!after || !*after)) {
        pa_log_info("policy decision point is gone");
        dbusif->regist = false;
        pdp_get_state_cancel(dbusif);
        pdp_register_ep_cancel(dbusif);
    } 
}

static void handle_info_message(struct userdata *u, DBusMessage *msg)
{
    dbus_uint32_t  txid;
    char          *app_id;
    char          *oper;
    char          *group;
    char          *arg;
    char          *method_str;
    char          *prop;
    int            success;
    enum pa_classify_method method = pa_method_unknown;

    success = dbus_message_get_args(msg, NULL,
                                    DBUS_TYPE_UINT32, &txid,
                                    DBUS_TYPE_STRING, &oper,
                                    DBUS_TYPE_STRING, &group,
                                    DBUS_TYPE_STRING, &app_id,
                                    DBUS_TYPE_STRING, &arg,
                                    DBUS_TYPE_STRING, &method_str,
                                    DBUS_TYPE_STRING, &prop,
                                    DBUS_TYPE_INVALID);
    if (!success) {
        pa_log("failed to parse info message");
        return;
    }

    if (arg && method_str) {
        switch (method_str[0]) {
        case 'e':
            if (!strcmp(method_str, "equals"))
                method = pa_method_equals;
            break;
        case 's':
            if (!strcmp(method_str, "startswith"))
                method = pa_method_startswith;
            break;
        case 'm':
            if (!strcmp(method_str, "matches"))
                method = pa_method_matches;
            break;
        case 't':
            if (!strcmp(method_str, "true"))
                method = pa_method_true;
            break;
        default:
            method = pa_method_unknown;
            break;
        }
    }

    if (arg && !strcmp(arg, "*"))
        method = pa_method_true;

    if (!strcmp(oper, "register")) {

        if (pa_policy_group_find(u, group) == NULL) {
            pa_log_debug("register client (%s|%s) failed: unknown group",
                         group, app_id);
        }
        else {
            pa_log_debug("register client (%s|%s)", group, app_id);
            pa_classify_register_app_id(u, app_id, prop, method, arg, group);
            pa_sink_input_ext_rediscover(u);
        }
    }
    else if (!strcmp(oper, "unregister")) {
        pa_log_debug("unregister client (%s|%s)", group, app_id);
        pa_classify_unregister_app_id(u, app_id, prop, method, arg);
    }
    else {
        pa_log("invalid operation: '%s'", oper);
    }
}

static void handle_action_message(struct userdata *u, DBusMessage *msg)
{
    static struct actdsc actions[] = {
        { "com.nokia.policy.audio_route" , audio_route_parser  },
        { "com.nokia.policy.volume_limit", volume_limit_parser },
        { "com.nokia.policy.audio_cork"  , audio_cork_parser   },
        { "com.nokia.policy.audio_mute"  , audio_mute_parser   },
        { "com.nokia.policy.context"     , context_parser      },
        {               NULL             , NULL                }
    };

    struct actdsc   *act;
    dbus_uint32_t    txid;
    char            *actname;
    DBusMessageIter  msgit;
    DBusMessageIter  arrit;
    DBusMessageIter  entit;
    DBusMessageIter  actit;
    int              success = true;

    pa_log_debug("got policy actions");

    dbus_message_iter_init(msg, &msgit);

    if (dbus_message_iter_get_arg_type(&msgit) != DBUS_TYPE_UINT32)
        return;

    dbus_message_iter_get_basic(&msgit, (void *)&txid);

    pa_log_debug("got actions (txid:%d)", txid);

    if (!dbus_message_iter_next(&msgit) ||
        dbus_message_iter_get_arg_type(&msgit) != DBUS_TYPE_ARRAY) {
        success = false;
        goto send_signal;
    }

    dbus_message_iter_recurse(&msgit, &arrit);

    do {
        if (dbus_message_iter_get_arg_type(&arrit) != DBUS_TYPE_DICT_ENTRY) {
            success = false;
            continue;
        }

        dbus_message_iter_recurse(&arrit, &entit);

        do {
            if (dbus_message_iter_get_arg_type(&entit) != DBUS_TYPE_STRING) {
                success = false;
                continue;
            }
            
            dbus_message_iter_get_basic(&entit, (void *)&actname);
            
            if (!dbus_message_iter_next(&entit) ||
                dbus_message_iter_get_arg_type(&entit) != DBUS_TYPE_ARRAY) {
                success = false;
                continue;
            }
            
            dbus_message_iter_recurse(&entit, &actit);
            
            if (dbus_message_iter_get_arg_type(&actit) != DBUS_TYPE_ARRAY) {
                success = false;
                continue;
            }
            
            for (act = actions;   act->name != NULL;   act++) {
                if (!strcmp(actname, act->name))
                    break;
            }
                                    
            if (act->parser != NULL)
                success &= act->parser(u, &actit);

        } while (dbus_message_iter_next(&entit));

    } while (dbus_message_iter_next(&arrit));

    pa_policy_context_variable_commit(u);

 send_signal:
    signal_status(u, txid, success);
}

static int action_parser(DBusMessageIter *actit, struct argdsc *descs,
                         void *args, int len)
{
    DBusMessageIter  cmdit;
    DBusMessageIter  argit;
    DBusMessageIter  valit;
    struct argdsc   *desc;
    char            *argname;
    void            *argval;
    
    dbus_message_iter_recurse(actit, &cmdit);

    memset(args, 0, len);

    do {
        if (dbus_message_iter_get_arg_type(&cmdit) != DBUS_TYPE_STRUCT)
            return false;

        dbus_message_iter_recurse(&cmdit, &argit);

        if (dbus_message_iter_get_arg_type(&argit) != DBUS_TYPE_STRING)
            return false;

        dbus_message_iter_get_basic(&argit, (void *)&argname);

        if (!dbus_message_iter_next(&argit))
            return false;

        if (dbus_message_iter_get_arg_type(&argit) != DBUS_TYPE_VARIANT)
            return false;

        dbus_message_iter_recurse(&argit, &valit);

        for (desc = descs;  desc->name != NULL;  desc++) {
            if (!strcmp(argname, desc->name)) {
                if (desc->offs + (int)sizeof(char *) > len) {
                    pa_log("%s(): desc offset %d is out of range %d",
                           __FUNCTION__, desc->offs, len);
                    return false;
                }
                else {
                    if (dbus_message_iter_get_arg_type(&valit) != desc->type)
                        return false;

                    argval = (char *)args + desc->offs;

                    dbus_message_iter_get_basic(&valit, argval);
                }
                break;
            }
        }

    } while (dbus_message_iter_next(&cmdit));

    return true;
}

static void port_changes_done_cb(struct userdata *u)
{
    pa_shared_data_inc_integer(u->shared, PA_SAILFISHOS_MEDIA_VOLUME_SYNC,
                                          PA_SAILFISHOS_MEDIA_VOLUME_CHANGE_DONE);
}

static int audio_route_parser(struct userdata *u, DBusMessageIter *actit)
{
    static struct argdsc descs[] = {
        {"type"  , STRUCT_OFFSET(struct argrt, type)  , DBUS_TYPE_STRING },
        {"device", STRUCT_OFFSET(struct argrt, device), DBUS_TYPE_STRING },
        {"mode"  , STRUCT_OFFSET(struct argrt, mode),   DBUS_TYPE_STRING },
        {"hwid"  , STRUCT_OFFSET(struct argrt, hwid),   DBUS_TYPE_STRING },
        {  NULL  ,            0                       , DBUS_TYPE_INVALID}
    };

    struct argrt args;
    pa_proplist *p = NULL;
    struct routing_decision decisions[MAX_ROUTING_DECISIONS];
    int num_decisions = 0;
    int num_decisions_done = 0;
    int i = 0;
    int num_moving = 0;
    bool result = true;
    bool route_changed = false;
    bool sink_route_changed = false;

    /* Parse message. It's safe to bail out here, because we're not moving any streams yet. */
    do {
        i = num_decisions;
        num_decisions++;

        if (num_decisions > MAX_ROUTING_DECISIONS) {
            pa_log_error("Too many routing decisions (max %d)", MAX_ROUTING_DECISIONS);
            return false;
        }

        if (!action_parser(actit, descs, &args, sizeof(args)))
            return false;

        if (args.type == NULL || args.device == NULL)
            return false;

        if (!strcmp(args.type, "sink"))
            decisions[i].class = pa_policy_route_to_sink;
        else if (!strcmp(args.type, "source"))
            decisions[i].class = pa_policy_route_to_source;
        else
            return false;

        decisions[i].target = args.device;
        decisions[i].mode   = (args.mode && strcmp(args.mode, "na")) ? args.mode : "";
        decisions[i].hwid   = (args.hwid && strcmp(args.hwid, "na")) ? args.hwid : "";

        pa_log_debug("route %s to %s (%s|%s)", args.type, decisions[i].target,
                                                          decisions[i].mode,
                                                          decisions[i].hwid);

        p = u->module->proplist;

        if (decisions[i].class == pa_policy_route_to_sink) {
            if (!pa_streq(pa_strempty(pa_proplist_gets(p, PROP_ROUTE_SINK_TARGET)), decisions[i].target) ||
                !pa_streq(pa_strempty(pa_proplist_gets(p, PROP_ROUTE_SINK_MODE  )), decisions[i].mode)   ||
                !pa_streq(pa_strempty(pa_proplist_gets(p, PROP_ROUTE_SINK_HWID  )), decisions[i].hwid)) {

                sink_route_changed = route_changed = true;
                pa_sink_ext_pending_start(u);
                pa_log_debug("Sink route has changed");

                pa_shared_data_inc_integer(u->shared, PA_SAILFISHOS_MEDIA_VOLUME_SYNC,
                                                      PA_SAILFISHOS_MEDIA_VOLUME_CHANGING);
            }
        } else {
            if (!pa_streq(pa_strempty(pa_proplist_gets(p, PROP_ROUTE_SOURCE_TARGET)), decisions[i].target) ||
                !pa_streq(pa_strempty(pa_proplist_gets(p, PROP_ROUTE_SOURCE_MODE  )), decisions[i].mode)   ||
                !pa_streq(pa_strempty(pa_proplist_gets(p, PROP_ROUTE_SOURCE_HWID  )), decisions[i].hwid)) {

                route_changed = true;
                pa_log_debug("Source route has changed");
            }
        }

    } while (dbus_message_iter_next(actit));

    if (!route_changed) {
        pa_log_debug("New audio route is identical to the current one. No need to move streams.");
        return true;
    }

    /* Detach groups. */
    num_moving = pa_policy_group_start_move_all(u);
    pa_log_debug("Policy groups moving: %d", num_moving);

    if (u->dbusif->route_sources_first) {
        /* Following works only if MAX_ROUTING_DECISIONS is 2, so make sure this is
         * caught if the value ever changes. */
        pa_assert_se(MAX_ROUTING_DECISIONS == 2);
        if (num_decisions > 1 && decisions[0].class != pa_policy_route_to_source) {
            struct routing_decision tmp = decisions[0];
            decisions[0] = decisions[1];
            decisions[1] = tmp;
        }
    }

    /* Set profiles and ports while the groups are detached. */
    for (i = 0; i < num_decisions; i++) {
        p = pa_proplist_new();

        if (decisions[i].class == pa_policy_route_to_sink) {
            pa_proplist_sets(p, PROP_ROUTE_SINK_TARGET, decisions[i].target);
            pa_proplist_sets(p, PROP_ROUTE_SINK_MODE,   decisions[i].mode);
            pa_proplist_sets(p, PROP_ROUTE_SINK_HWID,   decisions[i].hwid);
        } else {
            pa_proplist_sets(p, PROP_ROUTE_SOURCE_TARGET, decisions[i].target);
            pa_proplist_sets(p, PROP_ROUTE_SOURCE_MODE,   decisions[i].mode);
            pa_proplist_sets(p, PROP_ROUTE_SOURCE_HWID,   decisions[i].hwid);
        }

        pa_module_update_proplist(u->module, PA_UPDATE_REPLACE, p);
        pa_proplist_free(p);

        if (pa_card_ext_set_profile(u, decisions[i].target) < 0 ||
              (decisions[i].class == pa_policy_route_to_sink &&
                 pa_sink_ext_set_ports(u, decisions[i].target) < 0) ||
              (decisions[i].class == pa_policy_route_to_source &&
                 pa_source_ext_set_ports(u, decisions[i].target) < 0))
        {
            result = false; /* Continue anyway to avoid leaving streams detached. */
            pa_log_error("can't set profiles/ports to %s %s",
                         (decisions[i].class == pa_policy_route_to_sink ? "sink" : "source"),
                          decisions[i].target);
        }

        if (decisions[i].class == pa_policy_route_to_sink) {
            if (pa_policy_activity_device_changed(u, decisions[i].target) < 0)
                pa_log("Failed to update activity for %s", decisions[i].target);
        }
    }

    /* Attach groups to their new positions and re-attach those that were not moved. */
    for (i = 0; i < num_decisions; i++) {
        int num_moved;

        if ((num_moved = pa_policy_group_move_to(u, NULL, decisions[i].class,
                                                 decisions[i].target,
                                                 decisions[i].mode,
                                                 decisions[i].hwid)) < 0) {
            result = false;
            pa_log_error("Failed to move group %s %s %s", decisions[i].target,
                                                          decisions[i].mode,
                                                          decisions[i].hwid);
        } else {
            pa_log_debug("Moved %d %s groups to %s.",
                         num_moved,
                         decisions[i].class == pa_policy_route_to_sink ? "sink" : "source",
                         decisions[i].target);
            if (num_moving == num_moved)
                num_decisions_done++;
        }
    }

    /* Test that no moving groups exist */
    if (num_decisions != num_decisions_done) {
        pa_log_error("Got %d routing decisions. %d decisions were incomplete.",
                     num_decisions, num_decisions - num_decisions_done);

        pa_policy_group_assert_moving(u);
        result = false;
    }

    if (sink_route_changed)
        pa_sink_ext_pending_run(u, port_changes_done_cb);

    return result;
}

static int volume_limit_parser(struct userdata *u, DBusMessageIter *actit)
{
    static struct argdsc descs[] = {
        {"group", STRUCT_OFFSET(struct argvol, group), DBUS_TYPE_STRING },
        {"limit", STRUCT_OFFSET(struct argvol, limit), DBUS_TYPE_INT32  },
        {  NULL ,            0                       , DBUS_TYPE_INVALID}
    };

    struct argvol  args;
    int            success = true;

    do {
        if (!action_parser(actit, descs, &args, sizeof(args))) {
            success = false;
            break;
        }

        if (args.group == NULL || args.limit < 0 || args.limit > 100) {
            success = false;
            break;
        }

        pa_log_debug("volume limit (%s|%d)", args.group, args.limit); 

        pa_policy_group_volume_limit(u, args.group, (uint32_t)args.limit);

    } while (dbus_message_iter_next(actit));

    pa_sink_ext_set_volumes(u);

    return success;
}

static int audio_cork_parser(struct userdata *u, DBusMessageIter *actit)
{
    static struct argdsc descs[] = {
        {"group", STRUCT_OFFSET(struct argcork, group), DBUS_TYPE_STRING },
        {"cork" , STRUCT_OFFSET(struct argcork, cork) , DBUS_TYPE_STRING },
        { NULL  ,            0                        , DBUS_TYPE_INVALID}
    };
    
    struct argcork  args;
    char           *grp;
    int             val;
    
    do {
        if (!action_parser(actit, descs, &args, sizeof(args)))
            return false;

        if (args.group == NULL || args.cork == NULL)
            return false;

        grp = args.group;

        if (!strcmp(args.cork, "corked"))
            val = 1;
        else if (!strcmp(args.cork, "uncorked"))
            val = 0;
        else
            return false;
        
        pa_log_debug("cork stream (%s|%d)", grp, val);
        pa_policy_group_cork(u, grp, val);

    } while (dbus_message_iter_next(actit));
    
    return true;
}

static int audio_mute_parser(struct userdata *u, DBusMessageIter *actit)
{
    static struct argdsc descs[] = {
        {"device", STRUCT_OFFSET(struct argmute, device), DBUS_TYPE_STRING },
        {"mute"  , STRUCT_OFFSET(struct argmute, mute)  , DBUS_TYPE_STRING },
        { NULL   ,            0                         , DBUS_TYPE_INVALID}
    };
    
    struct argmute  args;
    char           *device;
    int             val;
    
    do {
        if (!action_parser(actit, descs, &args, sizeof(args)))
            return false;

        if (args.device == NULL || args.mute == NULL)
            return false;

        device = args.device;

        if (!strcmp(args.mute, "muted"))
            val = 1;
        else if (!strcmp(args.mute, "unmuted"))
            val = 0;
        else
            return false;
        
        pa_log_debug("mute device (%s|%d)", device, val);
        pa_source_ext_set_mute(u, device, val);

    } while (dbus_message_iter_next(actit));
    
    return true;
}

static int context_parser(struct userdata *u, DBusMessageIter *actit)
{
    static struct argdsc descs[] = {
        {"variable", STRUCT_OFFSET(struct argctx,variable), DBUS_TYPE_STRING },
        {"value"   , STRUCT_OFFSET(struct argctx,value)   , DBUS_TYPE_STRING },
        {  NULL    ,            0                         , DBUS_TYPE_INVALID}
    };
    
    struct argctx   args;
    
    do {
        if (!action_parser(actit, descs, &args, sizeof(args)))
            return false;

        if (args.variable == NULL || args.value == NULL)
            return false;

        pa_log_debug("context (%s|%s)", args.variable, args.value);

        pa_policy_context_variable_changed(u, args.variable, args.value);

    } while (dbus_message_iter_next(actit));
    
    return true;
}

static void getnameowner_cb(DBusPendingCall *pend, void *data)
{
    struct userdata         *u = data;
    DBusMessage             *reply;
    DBusError                error;

    pa_assert(u);
    pa_assert(u->dbusif);
    pa_assert(pend == u->dbusif->pending_pdp_state);

    reply = dbus_pending_call_steal_reply(pend);
    if (!reply) {
        pa_log("getting pdp state failed: invalid argument");
        return;
    }

    dbus_error_init(&error);

    if (dbus_set_error_from_message(&error, reply)) {
        pa_log_info("failed to get pdp state: %s (%s)",
                    error.name,
                    error.message ? error.message : "");
        dbus_error_free(&error);
    } else {
        pa_log_info("pdp is available");
        if (!u->dbusif->regist)
            pdp_register_ep(u->dbusif, u);
    }

    dbus_message_unref(reply);
    dbus_pending_call_unref(pend);
    u->dbusif->pending_pdp_state = NULL;
}

static void pdp_get_state(struct pa_policy_dbusif *dbusif, struct userdata *u)
{
    int              success = 0;
    DBusConnection  *conn    = pa_dbus_connection_get(dbusif->conn);
    DBusMessage     *msg     = NULL;
    DBusPendingCall *pend;

    msg = dbus_message_new_method_call(ADMIN_DBUS_MANAGER,
                                       ADMIN_DBUS_PATH,
                                       ADMIN_DBUS_INTERFACE,
                                       ADMIN_GET_NAME_OWNER);

    if (!msg) {
        pa_log("Failed to create D-Bus message to get pdp state");
        goto done;
    }

    if (!(success = dbus_message_append_args(msg,
                                             DBUS_TYPE_STRING, &dbusif->pdnam,
                                             DBUS_TYPE_INVALID))) {
        pa_log("Failed to build D-Bus message to get pdp state");
        goto done;
    }

    if (!(success = dbus_connection_send_with_reply(conn, msg, &pend, DBUS_TIMEOUT_USE_DEFAULT))) {
        pa_log("Failed to send message to get pdp state");
        goto done;
    }

    dbusif->pending_pdp_state = pend;

    if (!(success = dbus_pending_call_set_notify(pend, getnameowner_cb, u, NULL)))
        pa_log("Can't set notification for pdp state reply");

 done:
    if (msg)
        dbus_message_unref(msg);
    if (success)
        pa_log_debug("query initial pdp availability");
}

static void pdp_get_state_cancel(struct pa_policy_dbusif *dbusif)
{
    pa_assert(dbusif);

    if (dbusif->pending_pdp_state) {
        pa_log_debug("Canceling pending pdp state call.");
        dbus_pending_call_cancel(dbusif->pending_pdp_state);
        dbus_pending_call_unref(dbusif->pending_pdp_state);
        dbusif->pending_pdp_state = NULL;
    }
}

static void registration_cb(DBusPendingCall *pend, void *data)
{
    struct userdata *u = (struct userdata *)data;
    DBusMessage     *reply;
    DBusError        error;

    pa_assert(u);
    pa_assert(u->dbusif);
    pa_assert(pend == u->dbusif->pending_pdp_registration);

    reply = dbus_pending_call_steal_reply(pend);
    if (!reply) {
        pa_log("registartion setting failed: invalid argument");
        return;
    }

    dbus_error_init(&error);

    if (dbus_set_error_from_message(&error, reply)) {
        pa_log_info("registration to policy decision point failed: %s (%s)",
                    error.name,
                    error.message ? error.message : "");
        dbus_error_free(&error);
    } else {
        pa_log_info("got reply to registration");

        u->dbusif->regist = true;
        pa_log_info("Send state infos to policy decision point.");
        pa_policy_send_device_state_full(u);
    }

    dbus_message_unref(reply);
    dbus_pending_call_unref(pend);
    u->dbusif->pending_pdp_registration = NULL;
}

static int pdp_register_ep(struct pa_policy_dbusif *dbusif, struct userdata *u)
{
    static const char *name = "pulseaudio";

    int              success    = true;
    DBusConnection  *conn       = pa_dbus_connection_get(dbusif->conn);
    DBusMessage     *msg        = NULL;
    DBusPendingCall *pend       = NULL;
    const char      *signals[4];
    const char     **v_ARRAY;
    int              i;

    pa_assert(!dbusif->regist);

    if (dbusif->pending_pdp_registration)
        goto done;

    pa_log_info("registering to policy daemon: name='%s' path='%s' if='%s'",
                dbusif->pdnam, dbusif->pdpath, dbusif->ifnam);

    msg = dbus_message_new_method_call(dbusif->pdnam, dbusif->pdpath,
                                       dbusif->ifnam, "register");

    if (!msg) {
        pa_log("Failed to create D-Bus message to register");
        success = false;
        goto done;
    }

    signals[i=0] = POLICY_ACTIONS;
    v_ARRAY = signals;

    success = dbus_message_append_args(msg,
                                       DBUS_TYPE_STRING, &name,
                                       DBUS_TYPE_ARRAY,
                                       DBUS_TYPE_STRING, &v_ARRAY, i+1,
                                       DBUS_TYPE_INVALID);
    if (!success) {
        pa_log("Failed to build D-Bus message to register");
        goto done;
    }


    success = dbus_connection_send_with_reply(conn, msg, &pend, 10000);
    if (!success) {
        pa_log("Failed to register");
        goto done;
    }

    dbusif->pending_pdp_registration = pend;

    success = dbus_pending_call_set_notify(pend, registration_cb, u, NULL);

    if (!success) {
        pa_log("Can't set notification for registration");
    }

 done:
    if (msg)
        dbus_message_unref(msg);
    return success;
}

static void pdp_register_ep_cancel(struct pa_policy_dbusif *dbusif)
{
    pa_assert(dbusif);

    if (dbusif->pending_pdp_registration) {
        pa_log_debug("Canceling pending pdp registration call.");
        dbus_pending_call_cancel(dbusif->pending_pdp_registration);
        dbus_pending_call_unref(dbusif->pending_pdp_registration);
        dbusif->pending_pdp_registration = NULL;
    }
}

static int signal_status(struct userdata *u, uint32_t txid, uint32_t status)
{
    struct pa_policy_dbusif *dbusif = u->dbusif;
    DBusConnection          *conn   = pa_dbus_connection_get(dbusif->conn);
    DBusMessage             *msg;
    char                     path[256];
    int                      ret;

    if (txid == 0) {
    
        /* When transaction ID is 0, the policy manager does not expect
         * a response. */
        
        pa_log_debug("Not sending status message since transaction ID is 0");
        return 0;
    }

    snprintf(path, sizeof(path), "%s/%s", dbusif->pdpath, POLICY_DECISION);

    pa_log_debug("sending signal to: path='%s', if='%s' member='%s' "
                 "content: txid=%d status=%d", path, dbusif->ifnam,
                 POLICY_STATUS, txid, status);

    msg = dbus_message_new_signal(path, dbusif->ifnam, POLICY_STATUS);

    if (msg == NULL) {
        pa_log("failed to make new status message");
        goto fail;
    }

    ret = dbus_message_append_args(msg,
            DBUS_TYPE_UINT32, &txid,
            DBUS_TYPE_UINT32, &status,
            DBUS_TYPE_INVALID);

    if (!ret) {
        pa_log("Can't build D-Bus status message");
        goto fail;
    }

    ret = dbus_connection_send(conn, msg, NULL);

    if (!ret) {
        pa_log("Can't send status message: out of memory");
        goto fail;
    }

    dbus_message_unref(msg);

    return 0;

 fail:
    if (msg)
        dbus_message_unref(msg);

    return -1;
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */

