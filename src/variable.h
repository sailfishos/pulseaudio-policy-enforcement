#ifndef foovariablefoofoo
#define foovariablefoofoo

#include "userdata.h"

struct pa_policy_variable;

struct pa_policy_variable *pa_policy_var_init();
void pa_policy_var_done(struct pa_policy_variable *var);

void  pa_policy_var_add(struct userdata *u, const char *var, const char *value);
const char *pa_policy_var(struct userdata *u, const char *value);

#define pa_policy_var_update(userdata, var)  var = pa_policy_var(userdata, var)

#endif
