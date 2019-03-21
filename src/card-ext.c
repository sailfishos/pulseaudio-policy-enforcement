#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulse/def.h>
#include <pulsecore/device-port.h>
#include <pulsecore/card.h>

#include "card-ext.h"
#include "classify.h"
#include "context.h"
#include "policy.h"
#include "log.h"


/* hooks */
static pa_hook_result_t card_put(void *, void *, void *);
static pa_hook_result_t card_unlink(void *, void *, void *);
static pa_hook_result_t card_avail(void *, void *, void *);
static pa_hook_result_t card_profile_changed(void *, void *, void *);

static void handle_new_card(struct userdata *, struct pa_card *);
static void handle_removed_card(struct userdata *, struct pa_card *);
static void handle_card_profile_available_changed(struct userdata *u, pa_card *card);
static void handle_card_profile_changed(struct userdata *u, pa_card *card);


struct pa_card_evsubscr *pa_card_ext_subscription(struct userdata *u)
{
    pa_core                 *core;
    pa_hook                 *hooks;
    struct pa_card_evsubscr *subscr;
    pa_hook_slot            *put;
    pa_hook_slot            *unlink;
    pa_hook_slot            *avail;
    pa_hook_slot            *changed;

    pa_assert(u);
    pa_assert_se((core = u->core));

    hooks  = core->hooks;
    
    put    = pa_hook_connect(hooks + PA_CORE_HOOK_CARD_PUT,
                             PA_HOOK_LATE, card_put, (void *)u);
    unlink = pa_hook_connect(hooks + PA_CORE_HOOK_CARD_UNLINK,
                             PA_HOOK_LATE, card_unlink, (void *)u);
    avail  = pa_hook_connect(hooks + PA_CORE_HOOK_CARD_PROFILE_AVAILABLE_CHANGED,
                             PA_HOOK_LATE, card_avail, u);
    changed= pa_hook_connect(hooks + PA_CORE_HOOK_CARD_PROFILE_CHANGED,
                             PA_HOOK_LATE, card_profile_changed, u);

    subscr = pa_xnew0(struct pa_card_evsubscr, 1);
    
    subscr->put    = put;
    subscr->unlink = unlink;
    subscr->avail  = avail;
    subscr->changed= changed;

    return subscr;


}

void pa_card_ext_subscription_free(struct pa_card_evsubscr *subscr)
{
    if (subscr != NULL) {
        pa_hook_slot_free(subscr->put);
        pa_hook_slot_free(subscr->unlink);
        pa_hook_slot_free(subscr->avail);
        pa_hook_slot_free(subscr->changed);

        pa_xfree(subscr);
    }
}

void pa_card_ext_discover(struct userdata *u)
{
    void            *state = NULL;
    pa_idxset       *idxset;
    struct pa_card  *card;

    pa_assert(u);
    pa_assert(u->core);
    pa_assert_se((idxset = u->core->cards));

    while ((card = pa_idxset_iterate(idxset, &state, NULL)) != NULL)
        handle_new_card(u, card);
}

const char *pa_card_ext_get_name(struct pa_card *card)
{
    return card->name ? card->name : "<unknown>";
}

pa_hashmap *pa_card_ext_get_profiles(struct pa_card *card)
{
    pa_assert(card);
    pa_assert(card->profiles);

    return card->profiles;
}

int pa_card_ext_set_profile(struct userdata *u, char *type)
{    
    void            *state = NULL;
    pa_idxset       *idxset;
    struct pa_card  *card;
    struct pa_classify_card_data *data;
    struct pa_classify_card_data *datas[PA_POLICY_CARD_MAX_DEFS] = { NULL, NULL };
    struct pa_card  *cards[PA_POLICY_CARD_MAX_DEFS] = { NULL, NULL };
    int              priority;
    const char      *pn;
    const char      *override_pn;
    const char      *cn;
    pa_card_profile *ap;
    pa_card_profile *new_profile;
    int              sts;
    int              i;

    pa_assert(u);
    pa_assert(u->core);
    pa_assert_se((idxset = u->core->cards));

    sts = 0;

    while ((card = pa_idxset_iterate(idxset, &state, NULL)) != NULL) {
        if (pa_classify_is_card_typeof(u, card, type, &data, &priority)) {
            if (priority == 0) {
                datas[0] = data;
                cards[0] = card;
            }
            if (priority == 1) {
                datas[1] = data;
                cards[1] = card;
            }
        }
    }

    for (i = 0; i < PA_POLICY_CARD_MAX_DEFS && datas[i]; i++) {

        data = datas[i];
        card = cards[i];

        ap = card->active_profile;
        pn = data->profile;
        if (!pn)
            continue;

        if (pa_context_override_card_profile(u, card, pn, &override_pn))
            pn = override_pn;

        new_profile = pa_hashmap_get(card->profiles, pn);
        cn = pa_card_ext_get_name(card);

        if (new_profile && (!ap || ap != new_profile)) {
            if (pa_card_set_profile(card, new_profile, false) < 0) {
                sts = -1;
                pa_log("failed to set card '%s' profile to '%s'", cn, pn);
            }
            else
                pa_log_debug("changed card '%s' profile to '%s'", cn, pn);
        }
    }

    return sts;
}

static pa_hook_result_t card_put(void *hook_data, void *call_data,
                                 void *slot_data)
{
    struct pa_card  *card = (struct pa_card *)call_data;
    struct userdata *u    = (struct userdata *)slot_data;

    handle_new_card(u, card);

    return PA_HOOK_OK;
}


static pa_hook_result_t card_unlink(void *hook_data, void *call_data,
                                    void *slot_data)
{
    struct pa_card  *card = (struct pa_card *)call_data;
    struct userdata *u    = (struct userdata *)slot_data;

    handle_removed_card(u, card);

    return PA_HOOK_OK;
}

static pa_hook_result_t card_avail(void *hook_data, void *call_data,
                                   void *slot_data)
{
    pa_card_profile *cp = (pa_card_profile *) call_data;
    struct userdata *u  = (struct userdata *) slot_data;

    handle_card_profile_available_changed(u, cp->card);

    return PA_HOOK_OK;
}

static pa_hook_result_t card_profile_changed(void *hook_data, void *call_data,
                                             void *slot_data)
{
    pa_card         *card = call_data;
    struct userdata *u    = slot_data;

    handle_card_profile_changed(u, card);

    return PA_HOOK_OK;
}

static void handle_new_card(struct userdata *u, struct pa_card *card)
{
    struct pa_classify_result  *r;
    const char                 *name;
    uint32_t                    idx;
    int                         ret;
    char                       *buf;

    if (card && u) {
        name = pa_card_ext_get_name(card);
        idx  = card->index;

        pa_policy_context_register(u, pa_policy_object_card, name, card);

        if (pa_policy_log_level_debug()) {
            pa_classify_card(u, card, 0,0, false, &r);
            buf = pa_policy_log_concat(r->types, r->count);

            /* we don't usually need to save the type list to card property list
             * as it is not used for anything else than debugging. */
            ret = pa_proplist_sets(card->proplist,
                                   PA_PROP_POLICY_CARDTYPELIST, buf);
            if (ret < 0) {
                pa_log("failed to set property '%s' on card '%s'",
                       PA_PROP_POLICY_DEVTYPELIST, name);
            }

            pa_log_debug("new card '%s' (idx=%d%s%s)",
                         name, idx, r->count > 0 ? ", type=" : "", buf);
            pa_xfree(buf);
            pa_xfree(r);
        }

        pa_classify_card(u, card, PA_POLICY_DISABLE_NOTIFY, 0, true, &r);
        pa_policy_send_device_state(u, PA_POLICY_CONNECTED, r);
        pa_xfree(r);
    }
}

static void handle_removed_card(struct userdata *u, struct pa_card *card)
{
    const char *name;
    uint32_t  idx;
    struct pa_classify_result *r;
    char *buf;

    if (card && u) {
        name = pa_card_ext_get_name(card);
        idx  = card->index;

        pa_policy_context_unregister(u, pa_policy_object_card, name, card, idx);

        if (pa_policy_log_level_debug()) {
            pa_classify_card(u, card, 0, 0, false, &r);
            buf = pa_policy_log_concat(r->types, r->count);
            pa_log_debug("remove card '%s' (idx=%d%s%s)",
                         name, idx, r->count > 0 ? ", type=" : "", buf);
            pa_xfree(buf);
            pa_xfree(r);
        }

        pa_classify_card(u, card, PA_POLICY_DISABLE_NOTIFY, 0, false, &r);
        pa_policy_send_device_state(u, PA_POLICY_DISCONNECTED, r);
        pa_xfree(r);
    }
}

static void handle_card_profile_available_changed(struct userdata *u, pa_card *card)
{
    struct pa_classify_result *r;

    pa_classify_card(u, card, PA_POLICY_DISABLE_NOTIFY, 0, true, &r);
    pa_policy_send_device_state(u, PA_POLICY_CONNECTED, r);
    pa_xfree(r);
}

static void handle_card_profile_changed(struct userdata *u, pa_card *card)
{
    struct pa_classify_result  *r;
    pa_card_profile            *p;

    pa_classify_card(u, card, PA_POLICY_NOTIFY_PROFILE_CHANGED, PA_POLICY_NOTIFY_PROFILE_CHANGED,
                     true, &r);

    p = card->active_profile;

    if (r->count > 0) {
        if (pa_policy_log_level_debug()) {
            char *buf;
            buf = pa_policy_log_concat(r->types, r->count);
            pa_log_debug("card profile changed: type=\"%s\", profile=\"%s\"", buf, p->name);
            pa_xfree(buf);
        }

        pa_policy_send_card_state(u, r, p->name);
    }

    pa_xfree(r);
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
