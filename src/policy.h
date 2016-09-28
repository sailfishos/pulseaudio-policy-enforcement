#ifndef foopolicyfoo
#define foopolicyfoo

#include "userdata.h"

#define PA_POLICY_CONNECTED                "1"
#define PA_POLICY_DISCONNECTED             "0"

void pa_policy_send_device_state(struct userdata *u, const char *state,
                                 char *typelist);

#endif
