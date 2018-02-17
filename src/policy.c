#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulsecore/log.h>

#include "policy.h"
#include "dbusif.h"
#include "classify.h"
#include "log.h"

void pa_policy_send_device_state(struct userdata *u, const char *state,
                                 const struct pa_classify_result *list)
{
    pa_policy_dbusif_send_device_state(u, state, list);
}

void pa_policy_send_device_state_full(struct userdata *u)
{
    void             *state = NULL;
    pa_idxset        *idxset;
    struct pa_card   *card;
    struct pa_sink   *sink;
    struct pa_source *source;
    struct pa_classify_result *r;

    pa_assert(u);
    pa_assert(u->core);

    /* first reset all types to off */
    pa_classify_card_all_types(u, &r);
    pa_policy_dbusif_send_device_state(u, PA_POLICY_DISCONNECTED, r);
    pa_xfree(r);

    pa_classify_sink_all_types(u, &r);
    pa_policy_dbusif_send_device_state(u, PA_POLICY_DISCONNECTED, r);
    pa_xfree(r);

    pa_classify_source_all_types(u, &r);
    pa_policy_dbusif_send_device_state(u, PA_POLICY_DISCONNECTED, r);
    pa_xfree(r);

    /* cards */
    pa_assert_se((idxset = u->core->cards));
    state = NULL;

    while ((card = pa_idxset_iterate(idxset, &state, NULL))) {
        pa_classify_card(u, card, PA_POLICY_DISABLE_NOTIFY, 0,
                         true, &r);
        pa_policy_dbusif_send_device_state(u, PA_POLICY_CONNECTED, r);
        pa_xfree(r);
    }

    /* sinks */
    pa_assert_se((idxset = u->core->sinks));
    state = NULL;

    while ((sink = pa_idxset_iterate(idxset, &state, NULL))) {
        pa_classify_sink(u, sink, PA_POLICY_DISABLE_NOTIFY, 0, &r);
        pa_policy_dbusif_send_device_state(u, PA_POLICY_CONNECTED, r);
        pa_xfree(r);
    }

    /* sources */
    pa_assert_se((idxset = u->core->sources));
    state = NULL;

    while ((source = pa_idxset_iterate(idxset, &state, NULL))) {
        pa_classify_source(u, source, PA_POLICY_DISABLE_NOTIFY, 0, &r);
        pa_policy_dbusif_send_device_state(u, PA_POLICY_CONNECTED, r);
        pa_xfree(r);
    }
}
