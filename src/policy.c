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

