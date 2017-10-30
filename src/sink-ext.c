#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulse/def.h>
#include <pulse/rtclock.h>
#include <pulse/timeval.h>

#include <pulsecore/core-util.h>
#include <pulsecore/sink.h>
#include <pulsecore/namereg.h>

#include "sink-ext.h"
#include "index-hash.h"
#include "classify.h"
#include "context.h"
#include "policy-group.h"
#include "dbusif.h"
#include "policy.h"
#include "log.h"

struct delayed_port_change {
    struct userdata *userdata;
    char *sink_name;
    char *port_name;
    bool refresh;
    pa_time_event *event;
    PA_LLIST_FIELDS(struct delayed_port_change);
};

struct pa_sink_ext_data {
    struct userdata *userdata;
    PA_LLIST_HEAD(struct delayed_port_change, change_list);
    int32_t pending;
    pa_sink_ext_pending_cb pending_cb;
};

/* hooks */
static pa_hook_result_t sink_put(void *, void *, void *);
static pa_hook_result_t sink_unlink(void *, void *, void *);

static void handle_new_sink(struct userdata *, struct pa_sink *);
static void handle_removed_sink(struct userdata *, struct pa_sink *);

static void delayed_port_change_free(struct delayed_port_change *c);

struct pa_sink_ext_data *pa_sink_ext_new()
{
    struct pa_sink_ext_data *ext;

    ext = pa_xnew0 (struct pa_sink_ext_data, 1);
    PA_LLIST_HEAD_INIT(struct delayed_port_change, ext->change_list);

    return ext;
}

void pa_sink_ext_free(struct pa_sink_ext_data *ext)
{
    if (ext) {
        struct delayed_port_change *change;

        while (ext->change_list) {
            change = ext->change_list;
            PA_LLIST_REMOVE(struct delayed_port_change, ext->change_list, change);
            delayed_port_change_free(change);
        }
        pa_xfree(ext);
    }
}

struct pa_null_sink *pa_sink_ext_init_null_sink(const char *name)
{
    struct pa_null_sink *null_sink = pa_xnew0(struct pa_null_sink, 1);

    /* sink.null is temporary to de-couple PA releases from ours */
    null_sink->name = pa_xstrdup(name ? name : /* "null" */ "sink.null");
    null_sink->sink = NULL;

    return null_sink;
}

void pa_sink_ext_null_sink_free(struct pa_null_sink *null_sink)
{
    if (null_sink != NULL) {
        pa_xfree(null_sink->name);

        pa_xfree(null_sink);
    }
}

struct pa_sink_evsubscr *pa_sink_ext_subscription(struct userdata *u)
{
    pa_core                 *core;
    pa_hook                 *hooks;
    struct pa_sink_evsubscr *subscr;
    pa_hook_slot            *put;
    pa_hook_slot            *unlink;
    
    pa_assert(u);
    pa_assert_se((core = u->core));

    hooks  = core->hooks;
    
    put    = pa_hook_connect(hooks + PA_CORE_HOOK_SINK_PUT,
                             PA_HOOK_LATE, sink_put, (void *)u);
    unlink = pa_hook_connect(hooks + PA_CORE_HOOK_SINK_UNLINK,
                             PA_HOOK_LATE, sink_unlink, (void *)u);
    

    subscr = pa_xnew0(struct pa_sink_evsubscr, 1);
    
    subscr->put    = put;
    subscr->unlink = unlink;

    return subscr;
}

void  pa_sink_ext_subscription_free(struct pa_sink_evsubscr *subscr)
{
    if (subscr != NULL) {
        pa_hook_slot_free(subscr->put);
        pa_hook_slot_free(subscr->unlink);

        pa_xfree(subscr);
    }
}

void pa_sink_ext_discover(struct userdata *u)
{
    void            *state = NULL;
    pa_idxset       *idxset;
    struct pa_sink  *sink;

    pa_assert(u);
    pa_assert(u->core);
    pa_assert_se((idxset = u->core->sinks));

    while ((sink = pa_idxset_iterate(idxset, &state, NULL)) != NULL)
        handle_new_sink(u, sink);
}


struct pa_sink_ext *pa_sink_ext_lookup(struct userdata *u,struct pa_sink *sink)
{
    struct pa_sink_ext *ext;

    pa_assert(u);
    pa_assert(sink);

    ext = pa_index_hash_lookup(u->hsnk, sink->index);

    return ext;
}


const char *pa_sink_ext_get_name(struct pa_sink *sink)
{
    return sink->name ? sink->name : "<unknown>";
}

static int set_port(pa_sink *sink, const char *port, bool refresh);

static void delayed_port_change_free(struct delayed_port_change *c) {
    if (c->event)
        c->userdata->core->mainloop->time_free(c->event);
    pa_xfree(c->sink_name);
    pa_xfree(c->port_name);
    pa_xfree(c);
}

static void sink_ext_pending(struct userdata *u, int32_t change)
{
    u->sinkext->pending += change;
    if (u->sinkext->pending == 0) {
        if (u->sinkext->pending_cb)
            u->sinkext->pending_cb(u);
        u->sinkext->pending_cb = NULL;
    }
}

static void execute_change(struct userdata *u, struct delayed_port_change *port_change)
{
    pa_sink *sink;

    pa_assert(u);
    pa_assert(port_change);

    if ((sink = pa_namereg_get(u->core, port_change->sink_name, PA_NAMEREG_SINK)))
        set_port(sink, port_change->port_name, port_change->refresh);

    PA_LLIST_REMOVE(struct delayed_port_change, u->sinkext->change_list, port_change);
    delayed_port_change_free(port_change);
    sink_ext_pending(u, -1);
}

static void delay_cb(pa_mainloop_api *m, pa_time_event *e, const struct timeval *t, void *userdata)
{
    struct delayed_port_change *port_change = userdata;
    struct userdata *u = port_change->userdata;

    pa_assert(u);
    pa_assert(port_change->event == e);

    pa_log_info("start delayed port change (%s:%s).",
                port_change->sink_name, port_change->port_name);

    execute_change(u, port_change);
}

static int set_port(pa_sink *sink, const char *port, bool refresh) {
    int ret = 0;

    if (refresh) {
        if (sink->set_port) {
            pa_log_debug("refresh sink '%s' port to '%s'",
                         sink->name, port);
            sink->set_port(sink, sink->active_port);
        }
    } else {
        if (pa_sink_set_port(sink, port, false) < 0) {
            ret = -1;
            pa_log("failed to set sink '%s' port to '%s'",
                   sink->name, port);
        }
        else {
            pa_log_debug("changed sink '%s' port to '%s'",
                         sink->name, port);
        }
    }

    return ret;
}

static struct delayed_port_change *llist_append(struct delayed_port_change *list,
                                                struct delayed_port_change *item)
{
    struct delayed_port_change *i;

    if (list) {
        for (i = list; i->next; i = i->next) {};
        i->next = item;
        item->prev = i;
        item->next = NULL;
    } else {
        item->prev = item->next = NULL;
        list = item;
    }

    return list;
}

static int set_port_add(struct userdata *u, pa_sink *sink, const char *port,
                        const struct pa_classify_device_data *device, bool refresh) {
    struct delayed_port_change *change;
    int ret = 0;

    pa_assert(u);
    pa_assert(sink);
    pa_assert(port);

    if (device->flags & PA_POLICY_DELAYED_PORT_CHANGE && device->port_change_delay > 0) {
        change = pa_xnew0(struct delayed_port_change, 1);
        PA_LLIST_INIT(struct delayed_port_change, change);
        u->sinkext->change_list = llist_append(u->sinkext->change_list, change);
        change->userdata = u;
        change->sink_name = pa_xstrdup(sink->name);
        change->port_name = pa_xstrdup(port);
        change->refresh = refresh;
        change->event = pa_core_rttime_new(u->core, pa_rtclock_now() + device->port_change_delay, delay_cb, change);
        pa_log_info("queue delayed port change in %u us (%s:%s)", device->port_change_delay, sink->name, port);
        sink_ext_pending(u, 1);

        return ret;
    }

    return set_port(sink, port, refresh);
}

int pa_sink_ext_set_ports(struct userdata *u, const char *type)
{
    int ret = 0;
    pa_sink *sink;
    struct pa_classify_device_data *data;
    struct pa_classify_port_entry *port_entry;
    char *port;
    struct pa_sink_ext *ext;
    uint32_t idx;

    pa_assert(u);
    pa_assert(u->core);

    pa_classify_update_modules(u, PA_POLICY_MODULE_FOR_SINK, type);

    PA_IDXSET_FOREACH(sink, u->core->sinks, idx) {
        /* Check whether the port of this sink should be changed. */
        if (pa_classify_is_port_sink_typeof(u, sink, type, &data)) {

            pa_assert_se(port_entry = pa_hashmap_get(data->ports, sink->name));
            pa_assert_se(port = port_entry->port_name);

            ext  = pa_sink_ext_lookup(u, sink);
            if (!ext)
                continue;

            pa_classify_update_module(u, PA_POLICY_MODULE_FOR_SINK, data);

            if (ext->overridden_port) {
                pa_xfree(ext->overridden_port);
                ext->overridden_port = pa_xstrdup(port);
                continue;
            }

            if (!sink->active_port || !pa_streq(port,sink->active_port->name)){
                if (!ext->overridden_port) {
                    ret = set_port_add(u, sink, port, data, false);
                }
                continue;
            }

            if ((data->flags & PA_POLICY_REFRESH_PORT_ALWAYS) && !ext->overridden_port) {
                ret = set_port_add(u, sink, port, data, true);
                continue;
            }
        }
    } /* for */

    return ret;
}

void pa_sink_ext_pending_start(struct userdata *u)
{
    struct delayed_port_change *change;
    void *tmp;

    if (u->sinkext->pending != 0) {
        pa_log_info("execute and clear %d pending port change(s).", u->sinkext->pending);
        /* execute all previously pending changes before starting */
        PA_LLIST_FOREACH_SAFE(change, tmp, u->sinkext->change_list) {
            pa_log_info("execute pending port change (%s:%s).",
                        change->sink_name, change->port_name);
            execute_change(u, change);
        }
    }

    pa_assert(u->sinkext->pending == 0);
    pa_assert(u->sinkext->pending_cb == NULL);
}

void pa_sink_ext_pending_run(struct userdata *u, pa_sink_ext_pending_cb cb)
{
    pa_assert(u);
    pa_assert(cb);

    if (u->sinkext->pending == 0)
        cb(u);
    else
        u->sinkext->pending_cb = cb;
}

void pa_sink_ext_set_volumes(struct userdata *u)
{
    struct pa_sink     *sink;
    struct pa_sink_ext *ext;
    uint32_t            idx;

    pa_assert(u);
    pa_assert(u->core);

    PA_IDXSET_FOREACH(sink, u->core->sinks, idx) {
        ext = pa_sink_ext_lookup(u, sink);

        pa_assert(ext);

        if (ext->need_volume_setting) {
            pa_log_debug("set sink '%s' volume", pa_sink_ext_get_name(sink));
            pa_sink_set_volume(sink, NULL, true, false);
            ext->need_volume_setting = false;
        }
    }
}

void pa_sink_ext_override_port(struct userdata *u, struct pa_sink *sink,
                               char *port)
{
    struct pa_sink_ext *ext;
    const char         *name;
    uint32_t            idx;
    char               *active_port;

    if (!sink || !u || !port)
        return;

    name = pa_sink_ext_get_name(sink);
    idx  = sink->index;
    ext  = pa_sink_ext_lookup(u, sink);

    if (ext == NULL) {
        pa_log("no extension found for sink '%s' (idx=%u)", name, idx);
        return;
    }

    active_port = sink->active_port ? sink->active_port->name : "";

    if (ext->overridden_port) {
        if (strcmp(port, active_port)) {
            pa_log_debug("attempt to multiple time to override "
                         "port on sink '%s'", name);
        }
    }
    else {
        ext->overridden_port = pa_xstrdup(active_port);

        if (strcmp(port, active_port)) {
            if (pa_sink_set_port(sink, port, false) < 0)
                pa_log("failed to override sink '%s' port to '%s'", name,port);
            else
                pa_log_debug("overrode sink '%s' port to '%s'", name, port);
        }
    }
}

void pa_sink_ext_restore_port(struct userdata *u, struct pa_sink *sink)
{
    struct pa_sink_ext *ext;
    const char         *name;
    uint32_t            idx;
    const char         *active_port;
    char               *overridden_port;

    if (!sink || !u)
        return;

    name = pa_sink_ext_get_name(sink);
    idx  = sink->index;
    ext  = pa_sink_ext_lookup(u, sink);

    if (ext == NULL) {
        pa_log("no extension found for sink '%s' (idx=%u)", name, idx);
        return;
    }

    active_port     = sink->active_port ? sink->active_port->name : "";
    overridden_port = ext->overridden_port;

    if (overridden_port) {
        if (strcmp(overridden_port, active_port)) {
            if (pa_sink_set_port(sink, overridden_port, false) < 0) {
                pa_log("failed to restore sink '%s' port to '%s'",
                       name, overridden_port);
            }
            else {
                pa_log_debug("restore sink '%s' port to '%s'",
                             name, overridden_port);
            }
        }

        pa_xfree(overridden_port);
        ext->overridden_port = NULL;
    }
}

static pa_hook_result_t sink_put(void *hook_data, void *call_data,
                                 void *slot_data)
{
    struct pa_sink  *sink = (struct pa_sink *)call_data;
    struct userdata *u    = (struct userdata *)slot_data;

    handle_new_sink(u, sink);

    return PA_HOOK_OK;
}


static pa_hook_result_t sink_unlink(void *hook_data, void *call_data,
                                    void *slot_data)
{
    struct pa_sink  *sink = (struct pa_sink *)call_data;
    struct userdata *u    = (struct userdata *)slot_data;

    handle_removed_sink(u, sink);

    return PA_HOOK_OK;
}


static void handle_new_sink(struct userdata *u, struct pa_sink *sink)
{
    const char *name;
    uint32_t  idx;
    char      *buf;
    int       ret;
    struct pa_null_sink *ns;
    struct pa_sink_ext  *ext;
    struct pa_classify_result *r;

    if (sink && u) {
        name = pa_sink_ext_get_name(sink);
        idx  = sink->index;
        ns   = u->nullsink;

        if (!strcmp(name, ns->name)) {
            ns->sink = sink;
            pa_log_debug("new sink '%s' (idx=%d) will be used to "
                         "mute-by-route", name, idx);
        }

        pa_policy_context_register(u, pa_policy_object_sink, name, sink);
        pa_policy_activity_register(u, pa_policy_object_sink, name, sink);

        if (pa_policy_log_level_debug()) {
            pa_classify_sink(u, sink, 0, 0, &r);
            buf = pa_policy_log_concat(r->types, r->count);
            ret = pa_proplist_sets(sink->proplist,
                                   PA_PROP_POLICY_DEVTYPELIST, buf);

            if (ret < 0)
                pa_log("failed to set property '%s' on sink '%s'",
                       PA_PROP_POLICY_DEVTYPELIST, name);

            pa_log_debug("new sink '%s' (idx=%d%s%s)",
                         name, idx, r->count > 0 ? ", type=" : "", buf);
            pa_xfree(buf);
            pa_xfree(r);
        }

        ext = pa_xmalloc0(sizeof(struct pa_sink_ext));
        pa_index_hash_add(u->hsnk, idx, ext);

        pa_policy_groupset_update_default_sink(u, PA_IDXSET_INVALID);
        pa_policy_groupset_register_sink(u, sink);

        pa_classify_sink(u, sink, PA_POLICY_DISABLE_NOTIFY, 0, &r);
        pa_policy_send_device_state(u, PA_POLICY_CONNECTED, r);
        pa_xfree(r);
    }
}

static void handle_removed_sink(struct userdata *u, struct pa_sink *sink)
{
    const char          *name;
    uint32_t             idx;
    char                *buf;
    struct pa_null_sink *ns;
    struct pa_sink_ext  *ext;
    struct pa_classify_result *r;

    if (sink && u) {
        name = pa_sink_ext_get_name(sink);
        idx  = sink->index;
        ns   = u->nullsink;

        if (ns->sink == sink) {
            pa_log_debug("cease to use sink '%s' (idx=%u) to mute-by-route",
                         name, idx);

            /* TODO: move back the streams of this sink to their
               original place */

            ns->sink = NULL;
        }

        pa_policy_context_unregister(u, pa_policy_object_sink, name, sink,idx);
        pa_policy_activity_unregister(u, pa_policy_object_sink, name, sink,idx);

        if (pa_policy_log_level_debug()) {
            pa_classify_sink(u, sink, 0, 0, &r);
            buf = pa_policy_log_concat(r->types, r->count);
            pa_log_debug("remove sink '%s' (idx=%d%s%s)",
                         name, idx, r->count > 0 ? ", type=" : "", buf);
            pa_xfree(buf);
            pa_xfree(r);
        }

        pa_policy_groupset_update_default_sink(u, idx);
        pa_policy_groupset_unregister_sink(u, idx);

        if ((ext = pa_index_hash_remove(u->hsnk, idx)) == NULL)
            pa_log("no extension found for sink '%s' (idx=%u)",name, idx);
        else {
            pa_xfree(ext->overridden_port);
            pa_xfree(ext);
        }

        pa_classify_sink(u, sink, PA_POLICY_DISABLE_NOTIFY, 0, &r);
        pa_policy_send_device_state(u, PA_POLICY_DISCONNECTED, r);
        pa_xfree(r);
    }
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
