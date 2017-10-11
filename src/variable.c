#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulse/xmalloc.h>
#include <pulsecore/hashmap.h>

#include "variable.h"

struct pa_policy_variable {
    pa_hashmap *variables;
};

void  pa_policy_var_add(struct userdata *u, const char *var, const char *value)
{
    pa_assert(u);
    pa_assert(u->vars);

    if (!u->vars->variables)
        u->vars->variables = pa_hashmap_new_full(pa_idxset_string_hash_func,
                                                 pa_idxset_string_compare_func,
                                                 pa_xfree,
                                                 pa_xfree);

    if (pa_hashmap_get(u->vars->variables, var)) {
        pa_hashmap_remove_and_free(u->vars->variables, var);
        pa_log_debug("variable updated (%s|%s)", var, value);
    } else
        pa_log_debug("variable added (%s|%s)", var, value);

    pa_hashmap_put(u->vars->variables, pa_xstrdup(var), pa_xstrdup(value));
}

const char *pa_policy_var(struct userdata *u, const char *value)
{
    const char *lookup;
    const char *r;

    pa_assert(u);

    r = value;

    if (u->vars->variables && value) {
        if ((lookup = pa_hashmap_get(u->vars->variables, value)))
            r = lookup;
    }

    return r;
}

struct pa_policy_variable *pa_policy_var_init()
{
    return pa_xnew0(struct pa_policy_variable, 1);
}

void pa_policy_var_done(struct pa_policy_variable *vars)
{
    pa_assert(vars);

    if (vars->variables)
        pa_hashmap_free(vars->variables);

    pa_xfree(vars);
}
