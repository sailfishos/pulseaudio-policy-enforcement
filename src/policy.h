#ifndef foopolicyfoo
#define foopolicyfoo

#include "userdata.h"
#include "classify.h"

#define PA_POLICY_CONNECTED                "1"
#define PA_POLICY_DISCONNECTED             "0"

void pa_policy_send_device_state(struct userdata *u, const char *state,
                                 const struct pa_classify_result *list);
void pa_policy_send_device_state_full(struct userdata *u);
void pa_policy_send_card_state(struct userdata *u, const struct pa_classify_result *list,
                               const char *profile);

#endif
