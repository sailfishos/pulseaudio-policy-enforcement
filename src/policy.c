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

void pa_policy_send_device_state(struct userdata *u, const char *state,
                                 char *typelist)
{
#define MAX_TYPE 256

    const char *types[MAX_TYPE];
    int   ntype;
    char  buf[1024];
    char *p, *q, c;

    if (typelist && typelist[0]) {

        ntype = 0;

        p = typelist - 1;
        q = buf;

        do {
            p++;

            if (ntype < MAX_TYPE)
                types[ntype] = q;
            else {
                pa_log("%s() list overflow", __FUNCTION__);
                return;
            }

            while ((c = *p) != ' ' && c != '\0') {
                if (q < buf + sizeof(buf)-1)
                    *q++ = *p++;
                else {
                    pa_log("%s() buffer overflow", __FUNCTION__);
                    return;
                }
            }
            *q++ = '\0';
            ntype++;

        } while (*p);

        pa_policy_dbusif_send_device_state(u, state, types, ntype);
    }

#undef MAX_TYPE
}

void pa_policy_send_device_state_full(struct userdata *u)
{
    void             *state = NULL;
    pa_idxset        *idxset;
    struct pa_card   *card;
    struct pa_sink   *sink;
    struct pa_source *source;
    const char       *typelist;
    char              buf[1024];
    int               len;

    pa_assert(u);
    pa_assert(u->core);

    /* cards */
    pa_assert_se((idxset = u->core->cards));
    state = NULL;

    while ((card = pa_idxset_iterate(idxset, &state, NULL))) {
        len = pa_classify_card(u, card, PA_POLICY_DISABLE_NOTIFY, 0,
                               buf, sizeof(buf), true);
        if (len > 0)
            pa_policy_send_device_state(u, PA_POLICY_CONNECTED, buf);
    }

    /* sinks */
    pa_assert_se((idxset = u->core->sinks));
    state = NULL;

    while ((sink = pa_idxset_iterate(idxset, &state, NULL))) {
        len = pa_classify_sink(u, sink, PA_POLICY_DISABLE_NOTIFY, 0,
                               buf, sizeof(buf));
        if (len > 0)
            pa_policy_send_device_state(u, PA_POLICY_CONNECTED, buf);
    }

    /* sources */
    pa_assert_se((idxset = u->core->sources));
    state = NULL;

    while ((source = pa_idxset_iterate(idxset, &state, NULL))) {
        len = pa_classify_source(u, source, PA_POLICY_DISABLE_NOTIFY, 0,
                                 buf, sizeof(buf));
        if (len > 0)
            pa_policy_send_device_state(u, PA_POLICY_CONNECTED, buf);
    }
}
