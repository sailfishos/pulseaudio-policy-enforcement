#ifndef foopolicyfoo
#define foopolicyfoo

#include "userdata.h"
#include "classify.h"

#define PA_POLICY_CONNECTED                (true)
#define PA_POLICY_DISCONNECTED             (false)

void pa_policy_send_device_state(struct userdata *u, bool is_connected,
                                 const struct pa_classify_result *list);
void pa_policy_send_device_state_full(struct userdata *u);
void pa_policy_send_card_state(struct userdata *u, const struct pa_classify_result *list,
                               const char *profile);
void pa_policy_send_port_available_changed(struct userdata *u,
                                           const char *type,
                                           bool available);

#endif
