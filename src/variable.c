#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulse/xmalloc.h>
#include <pulsecore/hashmap.h>
#include <pulsecore/core-util.h>

#include "variable.h"

struct pa_policy_variable {
    pa_hashmap *variables;
};

void  pa_policy_var_add(struct userdata *u, const char *var, const char *value)
{
    bool update = false;
    const char *old_value;

    pa_assert(u);
    pa_assert(u->vars);

    if (!u->vars->variables)
        u->vars->variables = pa_hashmap_new_full(pa_idxset_string_hash_func,
                                                 pa_idxset_string_compare_func,
                                                 pa_xfree,
                                                 pa_xfree);

    if ((old_value = pa_hashmap_get(u->vars->variables, var))) {
        if (pa_streq(old_value, value))
            return;

        pa_hashmap_remove_and_free(u->vars->variables, var);
        update = true;
    }

    pa_log_debug("variable %s (%s|%s)", update ? "updated" : "added", var, value);
    pa_hashmap_put(u->vars->variables, pa_xstrdup(var), pa_xstrdup(value));
}

const char *pa_policy_var(struct userdata *u, const char *value)
{
    pa_assert(u);
    pa_assert(u->vars);

    if (u->vars->variables && value) {
        const char *found = NULL;
        const char *lookup = value;
        while ((lookup = pa_hashmap_get(u->vars->variables, lookup)))
            found = lookup;
        if (found)
            value = found;
    }

    if (value && *value == '$')
        pa_log("Undefined variable %s", value);

    return value;
}

struct pa_policy_variable *pa_policy_var_init()
{
    return pa_xnew0(struct pa_policy_variable, 1);
}

void pa_policy_var_done(struct pa_policy_variable *vars)
{
    if (!vars)
        return;

    if (vars->variables)
        pa_hashmap_free(vars->variables);

    pa_xfree(vars);
}
