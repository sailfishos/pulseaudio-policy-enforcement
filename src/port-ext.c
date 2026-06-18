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
#include <pulsecore/device-port.h>

#include "classify.h"
#include "policy.h"
#include "port-ext.h"

static pa_hook_result_t available_changed(void *hook_data, void *call_data,
                                          void *slot_data);
static void handle_available_changed(struct userdata *u, pa_device_port *p);

struct pa_port_evsubscr *pa_port_ext_subscription(struct userdata *u)
{
    pa_core                 *core;
    pa_hook                 *hooks;
    struct pa_port_evsubscr *subscr;

    pa_assert(u);
    pa_assert_se((core = u->core));

    hooks = core->hooks;

    subscr = pa_xnew0(struct pa_port_evsubscr, 1);

    subscr->available = pa_hook_connect(hooks + PA_CORE_HOOK_PORT_AVAILABLE_CHANGED,
                                        PA_HOOK_LATE, available_changed, u);

    return subscr;
}

void pa_port_ext_subscription_free(struct pa_port_evsubscr *subscr)
{
    if (!subscr)
        return;

    pa_hook_slot_free(subscr->available);
    pa_xfree(subscr);
}

void pa_port_ext_discover(struct userdata *u)
{
    pa_assert(u);
    pa_assert(u->portext);

    pa_card *card;
    uint32_t idx;

    PA_IDXSET_FOREACH(card, u->core->cards, idx) {
        pa_device_port *device_port;
        void *state;

        PA_HASHMAP_FOREACH(device_port, card->ports, state) {
            handle_available_changed(u, device_port);
        }
    }
}

static pa_hook_result_t available_changed(void *hook_data, void *call_data,
                                          void *slot_data)
{
    struct pa_device_port *port = call_data;
    struct userdata *u          = slot_data;

    handle_available_changed(u, port);

    return PA_HOOK_OK;
}

static void handle_available_changed(struct userdata *u, pa_device_port *p)
{
    struct pa_classify_result *result = NULL;
    pa_classify_port_get_device_types(u, p->direction, p->name, PA_POLICY_UPDATE_AVAILABLE, &result);

    for (int i = 0; i < result->count; i++)
        pa_policy_send_port_available_changed(u, result->types[i], p->available == PA_AVAILABLE_YES);

    pa_xfree(result);
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
