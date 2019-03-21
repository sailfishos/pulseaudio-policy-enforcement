#ifndef foocardextfoo
#define foocardextfoo

#include "userdata.h"

struct pa_card_evsubscr {
    pa_hook_slot    *put;
    pa_hook_slot    *unlink;
    pa_hook_slot    *avail;
    pa_hook_slot    *changed;
};

struct pa_card_evsubscr *pa_card_ext_subscription(struct userdata *);
void pa_card_ext_subscription_free(struct pa_card_evsubscr *);
void pa_card_ext_discover(struct userdata *);
const char *pa_card_ext_get_name(struct pa_card *);
pa_hashmap *pa_card_ext_get_profiles(struct pa_card *card);
int pa_card_ext_set_profile(struct userdata *, char *);

#endif

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
