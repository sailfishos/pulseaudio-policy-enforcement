#ifndef foopolicylogfoo
#define foopolicylogfoo

#include <pulsecore/log.h>

void pa_policy_log_init(bool debug);
pa_log_level_t pa_policy_log_level();
bool pa_policy_log_level_debug();
char *pa_policy_log_concat(const char **str, int count);

#endif
