#ifndef fooportextfoo
#define fooportextfoo

#include "userdata.h"

struct pa_port_evsubscr {
    pa_hook_slot    *available;
};

struct pa_port_evsubscr *pa_port_ext_subscription(struct userdata *u);
void  pa_port_ext_subscription_free(struct pa_port_evsubscr *subscr);
void  pa_port_ext_discover(struct userdata *u);

#endif
