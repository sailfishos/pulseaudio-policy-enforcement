#ifndef foodbusiffoo
#define foodbusiffoo

#include "userdata.h"
#include "classify.h"

struct pa_policy_dbusif;

struct pa_policy_dbusif *pa_policy_dbusif_init(struct userdata *, const char *,
                                               const char *, const char *,
                                               const char *, bool);
void pa_policy_dbusif_done(struct userdata *);
void pa_policy_dbusif_send_device_state(struct userdata *u, const char *state,
                                        const struct pa_classify_result *list);
void pa_policy_dbusif_send_media_status(struct userdata *, const char *,
                                        const char *, int);

void pa_policy_dbusif_send_card_profile_changed(struct userdata *u,
                                                const struct pa_classify_result *list,
                                                const char *profile);

#endif

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
