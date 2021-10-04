#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulsecore/client.h>
#include <pulsecore/core-util.h>
#include <pulsecore/log.h>
#include <pulsecore/sink-input.h>
#include <pulsecore/source-output.h>
#include <pulsecore/strbuf.h>
#include <pulsecore/core.h>
#include <pulsecore/hook-list.h>
#include <pulsecore/core-error.h>
#include <pulse/timeval.h>

#include "classify.h"
#include "policy-group.h"
#include "client-ext.h"
#include "sink-ext.h"
#include "source-ext.h"
#include "card-ext.h"
#include "sink-input-ext.h"
#include "source-output-ext.h"
#include "variable.h"
#include "context.h"
#include "match.h"



static const char *find_group_for_client(struct userdata *, struct pa_client *,
                                         pa_proplist *, uint32_t *);
#if 0
static char *arg_dump(int, char **, char *, size_t);
#endif

static void app_id_free(pa_classify_app_id *app);
static void app_id_map_free_all(pa_hashmap *app_id_map);
static void app_id_map_insert(pa_hashmap *app_id_map, const char *app_id,
                              const char *prop, enum pa_classify_method method,
                              const char *arg, const char *group);
static void app_id_map_remove(pa_hashmap *app_id_map, const char *app_id,
                              const char *prop, enum pa_classify_method method,
                              const char *arg);
static const char *app_id_get_group(pa_hashmap *map, const char *app_id,
                                    pa_proplist *proplist);
static pa_classify_app_id *app_id_map_find(pa_hashmap *app_id_map, const char *app_id,
                                           const char *prop, enum pa_classify_method method,
                                           const char *arg);

static void streams_free(struct pa_classify_stream_def *);
static void streams_add(struct userdata *u, struct pa_classify_stream_def **, const char *,
                        enum pa_classify_method, const char *, const char *,
                        const char *, uid_t, const char *, const char *, uint32_t,
                        const char *);
static const char *streams_get_group(struct userdata *u, struct pa_classify_stream_def **, pa_proplist *,
                                     const char *, uid_t, const char *, uint32_t *);
static struct pa_classify_stream_def
            *streams_find(struct userdata *u, struct pa_classify_stream_def **, pa_proplist *,
                          const char *, const char *, uid_t, const char *,
                          struct pa_classify_stream_def **);

static void device_def_free(struct pa_classify_device_def *d);
static void devices_free(struct pa_classify_device *);
static void devices_add(struct userdata *u, struct pa_classify_device **p_devices, const char *type,
                        enum pa_policy_object_type obj_type, const char *prop,
                        enum pa_classify_method method, const char *arg,
                        pa_idxset *ports, const char *module, const char *module_args,
                        uint32_t flags, uint32_t port_change_delay);
static int devices_classify(struct pa_classify_device *devices, const void *object,
                            uint32_t flag_mask, uint32_t flag_value,
                            struct pa_classify_result **result);
static int devices_is_typeof(struct pa_classify_device_def *defs, const void *object,
                             const char *type, struct pa_classify_device_data **data);

static void card_def_free(struct pa_classify_card_def *d);
static void cards_free(struct pa_classify_card *);
static void cards_add(struct userdata *u, struct pa_classify_card **, const char *,
                      enum pa_classify_method[PA_POLICY_CARD_MAX_DEFS], char **, char **,
                      uint32_t[PA_POLICY_CARD_MAX_DEFS]);
static int  cards_classify(struct pa_classify_card *, pa_card *, pa_hashmap *card_profiles,
                           uint32_t,uint32_t, bool reclassify, struct pa_classify_result **result);
static int card_is_typeof(struct pa_classify_card_def *, pa_card *card,
                          const char *, struct pa_classify_card_data **, int *priority);

static int port_device_is_typeof(struct pa_classify_device_def *,
                                 enum pa_policy_object_type obj_type,
                                 void *obj,
                                 const char *,
                                 struct pa_classify_device_data **);

static pa_hook_result_t module_unlink_hook_cb(pa_core *c, pa_module *m, struct pa_classify *cl);


static struct pa_classify_result *classify_result_malloc(uint32_t type_count)
{
    struct pa_classify_result *r;

    r = pa_xmalloc(sizeof(struct pa_classify_result) +
                   sizeof(char *) * (type_count > 0 ? type_count - 1 : 0));
    r->count = 0;

    return r;
}

static void classify_result_append(struct pa_classify_result **r, const char *type)
{
    (*r)->types[(*r)->count] = type;
    (*r)->count++;
}

static void unload_module(pa_module *m)
{
    if (m) {
#if (PULSEAUDIO_VERSION >= 8)
        pa_module_unload(m, true);
#else
        pa_module_unload(u->core, m, true);
#endif
    }
}

struct pa_classify *pa_classify_new(struct userdata *u)
{
    struct pa_classify *cl;

    cl = pa_xnew0(struct pa_classify, 1);

    cl->sinks   = pa_xnew0(struct pa_classify_device, 1);
    cl->sources = pa_xnew0(struct pa_classify_device, 1);
    cl->cards   = pa_xnew0(struct pa_classify_card, 1);
    cl->streams.app_id_map = pa_hashmap_new_full(pa_idxset_string_hash_func,
                                                 pa_idxset_string_compare_func,
                                                 pa_xfree,
                                                 NULL);

    return cl;
}

void pa_classify_free(struct userdata *u)
{
    struct pa_classify *cl = u->classify;
    uint32_t i;

    if (cl) {
        app_id_map_free_all(cl->streams.app_id_map);
        streams_free(cl->streams.defs);
        devices_free(cl->sinks);
        devices_free(cl->sources);
        cards_free(cl->cards);
        if (cl->module_unlink_hook_slot)
            pa_hook_slot_free(cl->module_unlink_hook_slot);

        for (i = 0; i < PA_POLICY_MODULE_COUNT; i++)
            unload_module(cl->module[i].module);

        pa_xfree(cl);
    }
}

void pa_classify_add_sink(struct userdata *u, const char *type, const char *prop,
                          enum pa_classify_method method, const char *arg,
                          pa_idxset *ports,
                          const char *module, const char *module_args,
                          uint32_t flags, uint32_t port_change_delay)
{
    struct pa_classify *classify;

    pa_assert(u);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->sinks);
    pa_assert(type);
    pa_assert(prop);
    pa_assert(arg);

    devices_add(u, &classify->sinks, type, pa_policy_object_sink, prop, method, arg, ports,
                module, module_args, flags, port_change_delay);
}

void pa_classify_add_source(struct userdata *u, const char *type, const char *prop,
                            enum pa_classify_method method, const char *arg,
                            pa_idxset *ports,
                            const char *module, const char *module_args,
                            uint32_t flags)
{
    struct pa_classify *classify;

    pa_assert(u);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->sources);
    pa_assert(type);
    pa_assert(prop);
    pa_assert(arg);

    devices_add(u, &classify->sources, type, pa_policy_object_source, prop, method, arg, ports,
                module, module_args, flags, 0);
}

void pa_classify_add_card(struct userdata *u, char *type,
                          enum pa_classify_method method[PA_POLICY_CARD_MAX_DEFS], char **arg,
                          char **profiles, uint32_t flags[PA_POLICY_CARD_MAX_DEFS])
{
    struct pa_classify *classify;

    pa_assert(u);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->cards);
    pa_assert(type);
    pa_assert(arg[0]);

    cards_add(u, &classify->cards, type, method, arg, profiles, flags);
}


void pa_classify_add_stream(struct userdata *u, const char *prop,
                            enum pa_classify_method method, const char *arg,
                            const char *clnam, const char *sname, uid_t uid,
                            const char *exe, const char *grnam,
                            uint32_t flags, const char *port,
                            const char *set_properties)
{
    struct pa_classify     *classify;
    struct pa_policy_group *group;

    pa_assert(u);
    pa_assert_se((classify = u->classify));

    /* update variables */
    pa_policy_var_update(u, prop);
    pa_policy_var_update(u, arg);
    pa_policy_var_update(u, clnam);
    pa_policy_var_update(u, sname);
    pa_policy_var_update(u, exe);
    pa_policy_var_update(u, grnam);
    pa_policy_var_update(u, port);
    pa_policy_var_update(u, set_properties);

    if (((prop && method && arg) || uid != (uid_t)-1 || exe) && grnam) {
        if (port) {
            if ((group = pa_policy_group_find(u, grnam)) == NULL) {
                flags &= ~PA_POLICY_LOCAL_ROUTE;
                pa_log("can't find group '%s' for stream", grnam);
            }
            else {
                group->portname = pa_xstrdup(port);
                pa_log_debug("set portname '%s' for group '%s'", port, grnam);
            }
        }

        streams_add(u, &classify->streams.defs, prop,method,arg,
                    clnam, sname, uid, exe, grnam, flags, set_properties);
    }
}

void pa_classify_update_stream_route(struct userdata *u, const char *sname)
{
    struct pa_classify_stream_def *stream;

    pa_assert(u);
    pa_assert(u->classify);

    for (stream = u->classify->streams.defs;  stream;  stream = stream->next) {
        if (stream->sname) {
            if (pa_streq(stream->sname, sname))
                stream->sact = 1;
            else
                stream->sact = 0;
            pa_log_debug("stream group %s changes to %s state", stream->group, stream->sact ? "active" : "inactive");
        }
    }
}

void pa_classify_register_app_id(struct userdata *u, const char *app_id, const char *prop,
                                 enum pa_classify_method method, const char *arg,
                                 const char *group)
{
    struct pa_classify *classify;

    pa_assert(u);
    pa_assert_se((classify = u->classify));

    if (app_id && group) {
        app_id_map_insert(classify->streams.app_id_map, app_id,
                          prop, method, arg, group);
    }
}

void pa_classify_unregister_app_id(struct userdata *u, const char *app_id, const char *prop,
                                   enum pa_classify_method method, const char *arg)
{
    struct pa_classify *classify;

    pa_assert(u);
    pa_assert_se((classify = u->classify));

    if (app_id) {
        app_id_map_remove(classify->streams.app_id_map, app_id,
                          prop, method, arg);
    }
}

const char *pa_classify_sink_input(struct userdata *u, struct pa_sink_input *sinp,
                                   uint32_t *flags)
{
    struct pa_client     *client;
    const char           *group;

    pa_assert(u);
    pa_assert(sinp);

    client = sinp->client;
    group  = find_group_for_client(u, client, sinp->proplist, flags);

    return group;
}

const char *pa_classify_sink_input_by_data(struct userdata *u,
                                           struct pa_sink_input_new_data *data,
                                           uint32_t *flags)
{
    struct pa_client     *client;
    const char           *group;

    pa_assert(u);
    pa_assert(data);

    client = data->client;
    group  = find_group_for_client(u, client, data->proplist, flags);

    return group;
}

const char *pa_classify_source_output(struct userdata *u,
                                      struct pa_source_output *sout)
{
    struct pa_client     *client;
    const char           *group;

    pa_assert(u);
    pa_assert(sout);

    client = sout->client;
    group  = find_group_for_client(u, client, sout->proplist, NULL);

    return group;
}

const char *
pa_classify_source_output_by_data(struct userdata *u,
                                  struct pa_source_output_new_data *data)
{
    struct pa_client     *client;
    const char           *group;

    pa_assert(u);
    pa_assert(data);

    client = data->client;
    group  = find_group_for_client(u, client, data->proplist, NULL);

    return group;
}

int pa_classify_sink(struct userdata *u, struct pa_sink *sink,
                     uint32_t flag_mask, uint32_t flag_value,
                     struct pa_classify_result **result)
{
    struct pa_classify *classify;
    struct pa_classify_device *devices;

    pa_assert(u);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->sinks);
    pa_assert_se((devices = classify->sinks));
    pa_assert(result);

    return devices_classify(devices, sink,
                            flag_mask, flag_value, result);
}

int pa_classify_source(struct userdata *u, struct pa_source *source,
                       uint32_t flag_mask, uint32_t flag_value,
                       struct pa_classify_result **result)
{
    struct pa_classify *classify;
    struct pa_classify_device *devices;

    pa_assert(u);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->sources);
    pa_assert_se((devices = classify->sources));
    pa_assert(result);

    return devices_classify(devices, source,
                            flag_mask, flag_value, result);
}

int pa_classify_card(struct userdata *u, struct pa_card *card,
                     uint32_t flag_mask, uint32_t flag_value,
                     bool reclassify, struct pa_classify_result **result)
{
    struct pa_classify *classify;
    struct pa_classify_card *cards;
    pa_hashmap *profs;

    pa_assert(u);
    pa_assert(result);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->cards);
    pa_assert_se((cards = classify->cards));

    profs = pa_card_ext_get_profiles(card);

    return cards_classify(cards, card, profs, flag_mask,flag_value, reclassify, result);
}

int pa_classify_card_all_types(struct userdata *u,
                               struct pa_classify_result **result)
{
    struct pa_classify *classify;
    struct pa_classify_card *cards;
    struct pa_classify_card_def  *d;

    pa_assert(u);
    pa_assert(result);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->cards);
    pa_assert_se((cards = classify->cards));

    *result = classify_result_malloc(cards->ndef);

    for (d = cards->defs;  d->type;  d++) {
        classify_result_append(result, d->type);
    }

    return (*result)->count;
}

static int devices_all_types(struct pa_classify_device *devices,
                             struct pa_classify_result **result)
{
    struct pa_classify_device_def *d;

    pa_assert(devices);
    pa_assert(result);

    *result = classify_result_malloc(devices->ndef);

    for (d = devices->defs;  d->type;  d++)
        classify_result_append(result, d->type);

    return (*result)->count;
}

int pa_classify_sink_all_types(struct userdata *u,
                               struct pa_classify_result **result)
{
    struct pa_classify *classify;
    struct pa_classify_device *devices;

    pa_assert(u);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->sinks);
    pa_assert_se((devices = classify->sinks));
    pa_assert(result);

    return devices_all_types(devices, result);
}

int pa_classify_source_all_types(struct userdata *u,
                                 struct pa_classify_result **result)
{
    struct pa_classify *classify;
    struct pa_classify_device *devices;

    pa_assert(u);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->sources);
    pa_assert_se((devices = classify->sources));
    pa_assert(result);

    return devices_all_types(devices, result);
}

int pa_classify_is_sink_typeof(struct userdata *u, struct pa_sink *sink,
                               const char *type,
                               struct pa_classify_device_data **d)
{
    struct pa_classify *classify;
    struct pa_classify_device_def *defs;

    pa_assert(u);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->sinks);
    pa_assert_se((defs = classify->sinks->defs));

    if (!sink || !type)
        return false;

    return devices_is_typeof(defs, sink, type, d);
}


int pa_classify_is_source_typeof(struct userdata *u, struct pa_source *source,
                                 const char *type,
                                 struct pa_classify_device_data **d)
{
    struct pa_classify *classify;
    struct pa_classify_device_def *defs;

    pa_assert(u);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->sources);
    pa_assert_se((defs = classify->sources->defs));

    if (!source || !type)
        return false;

    return devices_is_typeof(defs, source, type, d);
}


int pa_classify_is_card_typeof(struct userdata *u, struct pa_card *card,
                               const char *type, struct pa_classify_card_data **d, int *priority)
{
    struct pa_classify *classify;
    struct pa_classify_card_def *defs;

    pa_assert(u);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->cards);
    pa_assert_se((defs = classify->cards->defs));

    if (!card || !type)
        return false;

    return card_is_typeof(defs, card, type, d, priority);
}


int pa_classify_is_port_sink_typeof(struct userdata *u, struct pa_sink *sink,
                                    const char *type,
                                    struct pa_classify_device_data **d)
{
    struct pa_classify *classify;
    struct pa_classify_device_def *defs;

    pa_assert(u);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->sinks);
    pa_assert_se((defs = classify->sinks->defs));

    if (!sink || !type)
        return false;

    return port_device_is_typeof(defs, pa_policy_object_sink, sink, type, d);
}


int pa_classify_is_port_source_typeof(struct userdata *u,
                                      struct pa_source *source,
                                      const char *type,
                                      struct pa_classify_device_data **d)
{
    struct pa_classify *classify;
    struct pa_classify_device_def *defs;

    pa_assert(u);
    pa_assert_se((classify = u->classify));
    pa_assert(classify->sources);
    pa_assert_se((defs = classify->sources->defs));

    if (!source || !type)
        return false;

    return port_device_is_typeof(defs, pa_policy_object_source, source, type, d);
}


static int classify_update_module_load(struct userdata *u,
                                       uint32_t dir,
                                       struct pa_classify_module *m,
                                       struct pa_classify_device_data *devdata) {
    pa_assert(u);
    pa_assert(m);
    pa_assert(devdata);
    pa_assert(!m->module);

    pa_log_debug("Load module for %s: %s %s", dir == PA_POLICY_MODULE_FOR_SINK ? "sink" : "source",
                                              devdata->module,
                                              devdata->module_args ? devdata->module_args : "");

#if PULSEAUDIO_VERSION >= 12
    int r;
    if ((r = pa_module_load(&m->module,
                            u->core,
                            devdata->module,
                            devdata->module_args)) < 0) {
        pa_log("Failed to load %s: %s (%d)", devdata->module, pa_cstrerror(r), -r);
        return -1;
    }
#else
    m->module = pa_module_load(u->core,
                               devdata->module,
                               devdata->module_args);
    if (!m->module) {
        pa_log("Failed to load %s", devdata->module);
        return -1;
    }
#endif

    m->module_name = devdata->module;
    m->module_args = devdata->module_args;
    m->flags = devdata->flags;

    return 0;
}


static void classify_update_module_unload(struct userdata *u,
                                          uint32_t dir,
                                          struct pa_classify_module *m) {
    pa_assert(u);
    pa_assert(m);
    pa_assert(m->module);

    pa_log_debug("Unload %smodule for %s: %s",
                 m->flags & PA_POLICY_MODULE_UNLOAD_IMMEDIATELY ? "" : "request for ",
                 dir == PA_POLICY_MODULE_FOR_SINK ? "sink" : "source",
                 m->module_name);

    if (m->flags & PA_POLICY_MODULE_UNLOAD_IMMEDIATELY)
        unload_module(m->module);
    else
        pa_module_unload_request(m->module, true);

    m->module_name = NULL;
    m->module_args = NULL;
    m->module = NULL;
}


int pa_classify_update_module(struct userdata *u,
                              uint32_t dir,
                              struct pa_classify_device_data *devdata) {
    struct pa_classify_module *m;
    int ret = 0;

    pa_assert(u);
    pa_assert(devdata);
    pa_assert(dir < PA_POLICY_MODULE_COUNT);

    m = &u->classify->module[dir];

    if (m->module &&
        !pa_safe_streq(m->module_name, devdata->module) &&
        !pa_safe_streq(m->module_args, devdata->module_args))
        classify_update_module_unload(u, dir, m);

    if (devdata->module && !m->module)
        ret = classify_update_module_load(u, dir, m, devdata);

    return ret;
}


void pa_classify_update_modules(struct userdata *u, uint32_t dir, const char *type) {
    struct pa_classify_device_def *defs;
    struct pa_classify_device_def *d;
    struct pa_classify_device_def *new_def = NULL;
    struct pa_classify_module *m;
    bool need_to_unload = true;

    pa_assert(u);
    pa_assert(u->classify);
    pa_assert(u->classify->sources);
    pa_assert_se((defs = u->classify->sources->defs));

    m = &u->classify->module[dir];

    if (!m->module)
        return;

    for (d = defs;  d->type;  d++) {
        if (pa_streq(type, d->type)) {
            new_def = d;
            break;
        }
    }

    if (!new_def)
        return;

    for (d = defs;  d->type;  d++) {
        if (!pa_streq(type, d->type)) {
            if (d->data.module) {
                if (pa_safe_streq(m->module_name, new_def->data.module) &&
                    pa_safe_streq(m->module_args, new_def->data.module_args)) {
                    need_to_unload = false;
                    break;
                }
            }
        }
    }

    if (need_to_unload)
        classify_update_module_unload(u, dir, m);
}


static pa_hook_result_t module_unlink_hook_cb(pa_core *c, pa_module *m, struct pa_classify *cl) {
    uint32_t i;

    pa_assert(c);
    pa_assert(m);
    pa_assert(cl);

    for (i = 0; i < PA_POLICY_MODULE_COUNT; i++) {
        if (cl->module[i].module == m) {
            pa_log_debug("Module for %s unloading: %s",
                         i == PA_POLICY_MODULE_FOR_SINK ? "sink" : "source",
                         m->name);
            cl->module[i].module = NULL;
            cl->module[i].module_name = NULL;
            cl->module[i].module_args = NULL;
            break;
        }
    }

    return PA_HOOK_OK;
}


static const char *find_group_for_client(struct userdata  *u,
                                         struct pa_client *client,
                                         pa_proplist      *proplist,
                                         uint32_t         *flags_ret)
{
    struct pa_classify *classify;
    pa_hashmap *app_id_map;
    struct pa_classify_stream_def **defs;
    const char *app_id  = NULL;         /* client application id */
    const char *clnam   = "";           /* client's name in PA */
    uid_t       uid     = (uid_t) -1;   /* client process user ID */
    const char *exe     = "";           /* client's binary path */
    const char *group   = NULL;
    uint32_t    flags   = 0;

    assert(u);
    pa_assert_se((classify = u->classify));

    app_id_map = classify->streams.app_id_map;
    defs = &classify->streams.defs;

    if (client == NULL) {
        /* sample cache initiated sink-inputs don't have a client, but sample's proplist
         * contains PA_PROP_APPLICATION_PROCESS_BINARY anyway. Try to get this value
         * from proplist. This allows using 'exe' matching in stream definitions in xpolicy.conf
         * for sample cache initiated streams as well. */
        if (!(exe = pa_proplist_gets(proplist, PA_PROP_APPLICATION_PROCESS_BINARY)))
            exe = "";

        group = streams_get_group(u, defs, proplist, clnam, uid, exe, &flags);
    } else {
        app_id = pa_client_ext_app_id(client);

        if (!(group = app_id_get_group(app_id_map, app_id, proplist))) {

            pa_log("could not find group");
            clnam = pa_client_ext_name(client);
            uid   = pa_client_ext_uid(client);
            exe   = pa_client_ext_exe(client);

            group = streams_get_group(u, defs, proplist, clnam, uid, exe, &flags);
        }
    }

    if (group == NULL)
        group = PA_POLICY_DEFAULT_GROUP_NAME;

    pa_log_debug("%s (%s|%s|%d|%s) => %s,0x%x", __FUNCTION__,
                 clnam ? clnam : "<null>", app_id ? app_id : "<null>", uid,
                 exe ? exe : "<null>", group ? group : "<null>", flags);

    if (flags_ret != NULL)
        *flags_ret = flags;

    return group;
}

#if 0
static char *arg_dump(int argc, char **argv, char *buf, size_t len)
{
    char *p = buf;
    int   i, l;
    
    if (argc <= 0 || argv == NULL)
        snprintf(buf, len, "0 <null>");
    else {
        l = snprintf(p, len, "%d", argc);
        
        p   += l;
        len -= l;
        
        for (i = 0;  i < argc && len > 0;  i++) {
            l = snprintf(p, len, " [%d]=%s", i, argv[i]);
            
            p   += l;
            len -= l;
        }
    }
    
    return buf;
}
#endif

static void app_id_free(pa_classify_app_id *app)
{
    if (app) {
        pa_xfree(app->group);
        pa_xfree(app);
    }
}

static void app_id_map_free_all(pa_hashmap *app_id_map)
{
    if (app_id_map) {
        while (!pa_hashmap_isempty(app_id_map))
            app_id_free(pa_hashmap_steal_first(app_id_map));

        pa_hashmap_free(app_id_map);
    }
}

static void app_id_map_insert(pa_hashmap *app_id_map, const char *app_id,
                              const char *prop, enum pa_classify_method method,
                              const char *arg, const char *group)
{
    pa_classify_app_id *app;
    char *tmp = NULL;

    pa_assert(app_id_map);
    pa_assert(group);

    if ((app = app_id_map_find(app_id_map, app_id, prop, method, arg))) {
        if (app->match)
            tmp = pa_policy_match_def(app->match);

        pa_log_debug("app_id group changed (%s|%s) %s -> %s", app_id, tmp ? tmp : "",
                                                              app->group, group);

        pa_xfree(app->group);
        app->group = pa_xstrdup(group);
    } else {
        app = pa_xnew0(pa_classify_app_id, 1);

        app->group = pa_xstrdup(group);

        if (prop) {
            app->match = pa_policy_match_property_new(pa_policy_object_proplist,
                                                      prop,
                                                      method,
                                                      arg);
            if (!app->match)
                pa_log("failed to create match object for app_id %s group %s", app_id, app->group);
        }

        if (app->match)
            tmp = pa_policy_match_def(app->match);

        pa_hashmap_put(app_id_map, pa_xstrdup(app_id), app);

        pa_log_debug("app_id added (%s|%s) => %s", app_id,
                                                   tmp ? tmp : "",
                                                   app->group);
    }

    pa_xfree(tmp);
}

static void app_id_map_remove(pa_hashmap *app_id_map, const char *app_id,
                              const char *prop, enum pa_classify_method method,
                              const char *arg)
{
    pa_classify_app_id *app;

    if ((app = pa_hashmap_remove(app_id_map, app_id))) {
        pa_log_debug("app_id removed (%s) => %s", app_id, app->group);
        app_id_free(app);
    }
}

static const char *app_id_get_group(pa_hashmap *map, const char *app_id,
                                    pa_proplist *proplist)
{

    pa_classify_app_id *app;
    const char *group = NULL;

    pa_assert(map);

    if (app_id) {
        if ((app = pa_hashmap_get(map, app_id))) {
            if (!app->match)
                group = app->group;
            else if (pa_policy_match(app->match, proplist))
                group = app->group;
        }
    }

    return group;
}

static pa_classify_app_id *app_id_map_find(pa_hashmap *app_id_map, const char *app_id,
                                           const char *prop, enum pa_classify_method method,
                                           const char *arg)
{
    pa_classify_app_id *app = NULL;

    if ((app = pa_hashmap_get(app_id_map, app_id))) {
        if (!prop && !app->match)
            return app;

        if (app->match && method == pa_policy_match_method(app->match)) {
            if (method == pa_method_true)
                return app;

            if (pa_safe_streq(arg, pa_policy_match_arg(app->match)))
                return app;
        }
    }

    return NULL;
}

static void streams_free(struct pa_classify_stream_def *defs)
{
    struct pa_classify_stream_def *stream;
    struct pa_classify_stream_def *next;

    for (stream = defs;  stream;  stream = next) {
        next = stream->next;

        pa_policy_match_free(stream->stream_match);
        pa_xfree(stream->exe);
        pa_xfree(stream->clnam);
        pa_xfree(stream->sname);
        pa_xfree(stream->group);
        if (stream->properties)
            pa_proplist_free(stream->properties);

        pa_xfree(stream);
    }
}

static void streams_add(struct userdata *u, struct pa_classify_stream_def **defs, const char *prop,
                        enum pa_classify_method method, const char *arg, const char *clnam,
                        const char *sname, uid_t uid, const char *exe, const char *group, uint32_t flags,
                        const char *set_properties)
{
    struct pa_classify_stream_def *d;
    struct pa_classify_stream_def *prev;
    pa_proplist *proplist = NULL;
    char        *method_def = NULL;

    pa_assert(defs);
    pa_assert(group);

    proplist = pa_proplist_new();

    if (prop && arg && (method == pa_method_equals)) {
        pa_proplist_sets(proplist, prop, arg);
    }

    if ((d = streams_find(u, defs, proplist, clnam, sname, uid, exe, &prev)) != NULL) {
        pa_log_info("redefinition of stream");
        pa_xfree(d->group);
    }
    else {
        d = pa_xnew0(struct pa_classify_stream_def, 1);

        if (prop && arg) {
            d->stream_match = pa_policy_match_property_new(pa_policy_object_proplist,
                                                           prop,
                                                           method,
                                                           arg);
            if (!d->stream_match) {
                pa_log("%s: invalid stream definition [%s:%s]", __FUNCTION__, prop, arg);
                pa_xfree(d);
                return;
            }

            method_def = pa_policy_match_def(d->stream_match);
        }

        d->uid          = uid;
        d->exe          = exe   ? pa_xstrdup(exe)   : NULL;
        d->clnam        = clnam ? pa_xstrdup(clnam) : NULL;
        d->sname        = sname ? pa_xstrdup(sname) : NULL;
        d->sact         = sname ? 0 : -1;
        /* Stream action, identified streams' proplists are merged with what's defined here. */
        d->properties   = set_properties ? pa_proplist_from_string(set_properties) : NULL;

        prev->next = d;

        pa_log_debug("stream added (%d|%s|%s|%s|%d)", uid, exe?exe:"<null>",
                     clnam?clnam:"<null>", method_def, d->sact);
    }

    d->group = pa_xstrdup(group);
    d->flags = flags;

    pa_proplist_free(proplist);
    pa_xfree(method_def);
}

static const char *streams_get_group(struct userdata *u,
                                     struct pa_classify_stream_def **defs,
                                     pa_proplist *proplist,
                                     const char *clnam, uid_t uid, const char *exe,
                                     uint32_t *flags_ret)
{
    struct pa_classify_stream_def *d;
    const char *group;
    uint32_t flags;

    pa_assert(defs);

    if ((d = streams_find(u, defs, proplist, clnam, NULL, uid, exe, NULL)) == NULL) {
        group = NULL;
        flags = 0;
    }
    else {
        group = d->group;
        flags = d->flags;
    }

    if (flags_ret != NULL)
        *flags_ret = flags;

    if (d && d->properties)
        pa_proplist_update(proplist, PA_UPDATE_REPLACE, d->properties);

    return group;
}

static bool group_sink_is_active(struct userdata *u, const char *group_name)
{
    struct pa_policy_group *group;
    pa_sink *sink;

    if ((group = pa_policy_group_find(u, group_name))) {
        if (!(group->flags & PA_POLICY_GROUP_FLAG_DYNAMIC_SINK))
            return true;

        if ((sink = pa_policy_group_find_sink(u, group))) {
            pa_log_debug("sink %s is %srunning", sink->name, sink->state == PA_SINK_RUNNING ? "" : "not ");
            return sink->state == PA_SINK_RUNNING;
        }
    }

    return false;
}

static struct pa_classify_stream_def *
streams_find(struct userdata *u, struct pa_classify_stream_def **defs, pa_proplist *proplist,
             const char *clnam, const char *sname, uid_t uid, const char *exe,
             struct pa_classify_stream_def **prev_ret)
{
#define PROPERTY_MATCH     (!d->stream_match || pa_policy_match(d->stream_match, proplist))
#define STRING_MATCH_OF(m) (!d->m || (m && d->m && !strcmp(m, d->m)))
#define ID_MATCH_OF(m)     (d->m == -1 || m == d->m)

    struct pa_classify_stream_def *prev;
    struct pa_classify_stream_def *d;

    for (prev = (struct pa_classify_stream_def *)defs;
         (d = prev->next) != NULL;
         prev = prev->next)
    {
        if (PROPERTY_MATCH         &&
            STRING_MATCH_OF(clnam) &&
            ID_MATCH_OF(uid)       &&
            /* case for dynamically changing active sink. */
            (!sname || (sname && d->sname && !strcmp(sname, d->sname))) &&
            ((d->sact == -1 || d->sact == 1) && group_sink_is_active(u, d->group)) &&
            /* end special case */
            STRING_MATCH_OF(exe)      )
            break;

    }

    if (prev_ret)
        *prev_ret = prev;

#if 0
    {
        char *s = pa_proplist_to_string_sep(proplist, " ");
        pa_log_debug("%s(<%s>,'%s',%d,'%s') => %p", __FUNCTION__,
                     s, clnam?clnam:"<null>", uid, exe?exe:"<null>", d);
        pa_xfree(s);
    }
#endif

    return d;

#undef PROPERTY_MATCH
#undef STRING_MATCH_OF
#undef ID_MATCH_OF
}

static void classify_port_entry_free(void *data) {
    struct pa_classify_port_entry *port = data;

    pa_assert(port);

    pa_policy_match_free(port->device_match);
    pa_xfree(port->port_name);
    pa_xfree(port);
}

static void device_def_free(struct pa_classify_device_def *d)
{
    pa_assert(d);

    pa_xfree(d->type);

    if (d->data.ports)
        pa_idxset_free(d->data.ports, classify_port_entry_free);

    pa_policy_match_free(d->dev_match);

    pa_xfree(d->data.module);
        pa_xfree(d->data.module_args);
}

static void devices_free(struct pa_classify_device *devices)
{
    struct pa_classify_device_def *d;

    if (devices) {
        for (d = devices->defs;  d->type;  d++)
            device_def_free(d);

        pa_xfree(devices);
    }
}

static void devices_add(struct userdata *u, struct pa_classify_device **p_devices, const char *type,
                        enum pa_policy_object_type obj_type, const char *prop,
                        enum pa_classify_method method, const char *arg,
                        pa_idxset *ports, const char *module, const char *module_args,
                        uint32_t flags, uint32_t port_change_delay)
{
    struct pa_classify_device *devs;
    struct pa_classify_device_def *d;
    size_t newsize;
    char *ports_string = NULL; /* Just for log output. */
    pa_strbuf *buf; /* For building ports_string. */
    bool replace = false;

    pa_assert(p_devices);
    pa_assert_se((devs = *p_devices));

    /* update variables */
    pa_policy_var_update(u, type);
    pa_policy_var_update(u, prop);
    pa_policy_var_update(u, arg);
    pa_policy_var_update(u, module);
    pa_policy_var_update(u, module_args);

    for (d = devs->defs;  d->type;  d++) {
        if (pa_streq(type, d->type)) {
            replace = true;
            break;
        }
    }

    if (replace && d) {
        device_def_free(d);
        memset(d, 0, sizeof(*d));
    } else {
        newsize = sizeof(*devs) + sizeof(devs->defs[0]) * (devs->ndef + 1);
        devs = *p_devices = pa_xrealloc(devs, newsize);
        d = devs->defs + devs->ndef;
        memset(d+1, 0, sizeof(devs->defs[0]));
    }

    d->dev_match = pa_policy_match_new(obj_type,
                                       pa_streq(prop, "(name)") ? pa_object_name : pa_object_property,
                                       prop,
                                       method,
                                       arg);

    if (!d->dev_match) {
        pa_log("%s: invalid device definition %s", __FUNCTION__, type);
        memset(d, 0, sizeof(*d));
        return;
    }

    d->type = pa_xstrdup(type);

    buf = pa_strbuf_new();

    if (ports && !pa_idxset_isempty(ports)) {
        struct pa_classify_port_config_entry *port_config;
        struct pa_classify_port_entry *port;
        char *port_entry_tmp;
        uint32_t idx;
        bool first = true;

        /* Copy the ports idxset to d->data.ports. */

        d->data.ports = pa_idxset_new(NULL, NULL);

        PA_IDXSET_FOREACH(port_config, ports, idx) {
            port = pa_xnew0(struct pa_classify_port_entry, 1);

            port->port_name = pa_xstrdup(pa_policy_var(u, port_config->port_name));
            port->device_match = pa_policy_match_new(obj_type,
                                                     pa_streq(port_config->prop, "(name)") ?
                                                        pa_object_name : pa_object_property,
                                                     pa_policy_var(u, port_config->prop),
                                                     port_config->method,
                                                     pa_policy_var(u, port_config->arg));

            pa_idxset_put(d->data.ports, port, NULL);

            if (!first)
                pa_strbuf_putc(buf, ',');
            first = false;

            port_entry_tmp = pa_policy_match_def(port->device_match);
            pa_strbuf_printf(buf, "%s:%s", port_entry_tmp, port->port_name);
            pa_xfree(port_entry_tmp);
        }
    }

    d->data.module = module ? pa_xstrdup(module) : NULL;
    d->data.module_args = module_args ? pa_xstrdup(module_args) : NULL;

    if (d->data.module && !u->classify->module_unlink_hook_slot)
        u->classify->module_unlink_hook_slot = pa_hook_connect(&u->core->hooks[PA_CORE_HOOK_MODULE_UNLINK],
                                                               PA_HOOK_NORMAL,
                                                               (pa_hook_cb_t) module_unlink_hook_cb,
                                                               u->classify);

    d->data.flags = flags;
    d->data.port_change_delay = port_change_delay * PA_USEC_PER_MSEC;

    devs->ndef++;

#if (PULSEAUDIO_VERSION >= 8)
    ports_string = pa_strbuf_to_string_free(buf);
#else
    ports_string = pa_strbuf_tostring_free(buf);
#endif

    pa_log_info("device '%s' %s (%s|%s|%s|%s|0x%04x)",
                type, replace ? "updated" : "added", prop,
                pa_match_method_str(method), arg, ports_string, d->data.flags);

    pa_xfree(ports_string);
}

static int devices_classify(struct pa_classify_device *devices, const void *object,
                            uint32_t flag_mask, uint32_t flag_value,
                            struct pa_classify_result **result)
{
    struct pa_classify_device_def *d;

    pa_assert(result);

    *result = classify_result_malloc(devices->ndef);

    for (d = devices->defs;  d->type;  d++) {
        if (pa_policy_match(d->dev_match, object)) {
            if ((d->data.flags & flag_mask) == flag_value) {
                pa_assert((*result)->count < devices->ndef);
                classify_result_append(result, d->type);
            }
        }
    }

    return (*result)->count;
}

static int devices_is_typeof(struct pa_classify_device_def *defs, const void *object,
                             const char *type, struct pa_classify_device_data **data)
{
    struct pa_classify_device_def *d;

    for (d = defs;  d->type;  d++) {
        if (!strcmp(type, d->type)) {
            if (pa_policy_match(d->dev_match, object)) {
                if (data != NULL)
                    *data = &d->data;

                return true;
            }
        }
    }

    return false;
}

static void card_def_free(struct pa_classify_card_def *d)
{
    int i;

    pa_assert(d);

    pa_xfree(d->type);

    for (i = 0; i < PA_POLICY_CARD_MAX_DEFS; i++) {
        pa_xfree(d->data[i].profile);
        pa_policy_match_free(d->data[i].card_match);
    }
}

static void cards_free(struct pa_classify_card *cards)
{
    struct pa_classify_card_def *d;

    if (cards) {
        for (d = cards->defs;  d->type;  d++)
            card_def_free(d);

        pa_xfree(cards);
    }
}

static void cards_add(struct userdata *u, struct pa_classify_card **p_cards,
                      const char *type, enum pa_classify_method method[PA_POLICY_CARD_MAX_DEFS],
                      char **arg, char **profiles, uint32_t flags[PA_POLICY_CARD_MAX_DEFS])
{
    struct pa_classify_card *cards;
    struct pa_classify_card_def *d;
    struct pa_classify_card_data *data;
    size_t newsize;
    const char *arg_str;
    int i;
    bool replace = false;

    pa_assert(p_cards);
    pa_assert_se((cards = *p_cards));

    /* update variable */
    pa_policy_var_update(u, type);

    for (d = cards->defs;  d->type;  d++) {
        if (pa_streq(type, d->type)) {
            replace = true;
            break;
        }
    }

    if (replace && d) {
        card_def_free(d);
        memset(d, 0, sizeof(*d));
    } else {
        newsize = sizeof(*cards) + sizeof(cards->defs[0]) * (cards->ndef + 1);
        cards = *p_cards = pa_xrealloc(cards, newsize);
        d = cards->defs + cards->ndef;
        memset(d+1, 0, sizeof(cards->defs[0]));
    }

    d->type    = pa_xstrdup(type);

    for (i = 0; i < PA_POLICY_CARD_MAX_DEFS && profiles[i]; i++) {

        data = &d->data[i];

        data->profile = profiles[i] ? pa_xstrdup(pa_policy_var(u, profiles[i])) : NULL;
        data->flags   = flags[i];
        arg_str = pa_policy_var(u, arg[i]);

        if (method[i] == pa_method_true)
            goto fail;

        data->card_match = pa_policy_match_name_new(pa_policy_object_card,
                                                    method[i],
                                                    arg_str);
        if (!data->card_match)
            goto fail;
    }

    cards->ndef++;

    pa_log_info("card '%s' %s (%s|%s|%s|0x%04x)", type, replace ? "updated" : "added",
                pa_match_method_str(method[0]), pa_policy_var(u, arg[0]),
                d->data[0].profile ? d->data[0].profile : "", d->data[0].flags);
    if (d->data[1].profile)
        pa_log_info("  :: %s (%s|%s|%s|0x%04x)", replace ? "updated" : "added",
                    pa_match_method_str(method[1]), pa_policy_var(u, arg[1]),
                    d->data[1].profile ? d->data[1].profile : "", d->data[1].flags);

    return;

fail:
    pa_log("%s: invalid card definition %s", __FUNCTION__, type);
    memset(d, 0, sizeof(*d));
}

static int cards_classify(struct pa_classify_card *cards,
                          pa_card *card, pa_hashmap *card_profiles,
                          uint32_t flag_mask, uint32_t flag_value,
                          bool reclassify, struct pa_classify_result **result)
{
    struct pa_classify_card_def  *d;
    struct pa_classify_card_data *data;
    pa_card_profile *cp;
    int              i;
    bool             supports_profile;

    pa_assert(result);

    /* one card definition may have multiple sets of defines */
    *result = classify_result_malloc(cards->ndef * PA_POLICY_CARD_MAX_DEFS);

    for (d = cards->defs;  d->type;  d++) {

        /* Check for all definition sets */

        for (i = 0; i < PA_POLICY_CARD_MAX_DEFS && d->data[i].profile; i++) {

            data = &d->data[i];

            if (pa_policy_match(data->card_match, card)) {
                supports_profile = false;

                if (data->profile == NULL)
                    supports_profile = true;
                else {
                    if ((cp = pa_hashmap_get(card_profiles, data->profile))) {
                        if (!reclassify || cp->available != PA_AVAILABLE_NO)
                            supports_profile = true;
                    }
                }

                if (supports_profile && (data->flags & flag_mask) == flag_value) {
                    pa_assert((*result)->count < cards->ndef);
                    classify_result_append(result, d->type);
                }
            }
        }

    }

    return (*result)->count;
}

static int card_is_typeof(struct pa_classify_card_def *defs, pa_card *card,
                          const char *type, struct pa_classify_card_data **data, int *priority)
{
    struct pa_classify_card_def *d;
    int i;

    for (d = defs;  d->type;  d++) {
        if (!strcmp(type, d->type)) {

            for (i = 0; i < PA_POLICY_CARD_MAX_DEFS && d->data[i].profile; i++) {
                if (pa_policy_match(d->data[i].card_match, card)) {
                    if (data != NULL)
                        *data = &d->data[i];
                    if (priority != NULL)
                        *priority = i;

                    return true;
                }
            }
        }
    }

    return false;
}

static int port_device_is_typeof(struct pa_classify_device_def *defs,
                                 enum pa_policy_object_type obj_type,
                                 void *obj,
                                 const char *type,
                                 struct pa_classify_device_data **data)
{
    struct pa_classify_device_def *d;

    for (d = defs;  d->type;  d++) {
        if (pa_streq(type, d->type)) {
            if (d->data.ports && pa_classify_get_port_entry(&d->data, obj_type, obj)) {
                if (data)
                    *data = &d->data;

                return true;
            }
        }
    }

    return false;
}

struct pa_classify_port_entry *pa_classify_get_port_entry(struct pa_classify_device_data *data,
                                                          enum pa_policy_object_type obj_type,
                                                          void *obj)
{
    struct pa_classify_port_entry *port;
    uint32_t idx;

    pa_assert(data);
    pa_assert(obj);
    pa_assert(obj_type == pa_policy_object_sink || obj_type == pa_policy_object_source);

    PA_IDXSET_FOREACH(port, data->ports, idx) {
        if (pa_policy_match_type(port->device_match, obj_type, obj))
            return port;
    }

    return NULL;
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
