#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulsecore/log.h>
#include <pulsecore/strbuf.h>
#include "log.h"

#ifndef ENV_LOG_LEVEL
#define ENV_LOG_LEVEL "PULSE_LOG"
#endif

static pa_log_level_t log_level = PA_LOG_ERROR;

void pa_policy_log_init(bool debug)
{
    const char *e;

    if (debug)
        log_level = PA_LOG_LEVEL_MAX - 1;
    else {
        if ((e = getenv(ENV_LOG_LEVEL))) {
            log_level = (pa_log_level_t) atoi(e);

            if ((unsigned int) log_level >= PA_LOG_LEVEL_MAX)
                log_level = PA_LOG_LEVEL_MAX - 1;
        }
    }
}

pa_log_level_t pa_policy_log_level()
{
    return log_level;
}

bool pa_policy_log_level_debug()
{
    if (PA_UNLIKELY(log_level == PA_LOG_DEBUG))
        return true;
    else
        return false;
}

char *pa_policy_log_concat(const char **str, int count)
{
    pa_strbuf *buf;
    int i;

    buf = pa_strbuf_new();

    for (i = 0; i < count; i++) {
        if (i > 0)
            pa_strbuf_putc(buf, ' ');
        pa_strbuf_puts(buf, str[i]);
    }

    return pa_strbuf_to_string_free(buf);
}
