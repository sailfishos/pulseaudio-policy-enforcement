#include <stdio.h>
#include <stdbool.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulsecore/client.h>
#include <pulsecore/core-util.h>
#include <pulsecore/log.h>
#include <pulsecore/sink-input.h>
#include <pulsecore/source-output.h>
#include <pulsecore/strbuf.h>
#include <pulsecore/core.h>
#include <pulsecore/hook-list.h>

#include "match.h"

/* #define DEBUG_MATCH 1 */

const char *pa_policy_object_type_str(enum pa_policy_object_type obj_type)
{
    switch (obj_type) {
        case pa_policy_object_module:           return "module";
        case pa_policy_object_card:             return "card";
        case pa_policy_object_sink:             return "sink";
        case pa_policy_object_source:           return "source";
        case pa_policy_object_sink_input:       return "sink-input";
        case pa_policy_object_source_output:    return "source-output";
        case pa_policy_object_port:             return "port";
        case pa_policy_object_profile:          return "profile";
        case pa_policy_object_proplist:         return "proplist";
        default:                                return "<unknown>";
    }

    return "<unknown>";
}

static const char *method_str(enum pa_classify_method method)
{
    switch (method) {
        default:
        case pa_method_unknown:                 return "unknown";
        case pa_method_equals:                  return "equals";
        case pa_method_startswith:              return "startswith";
        case pa_method_matches:                 return "matches";
        case pa_method_true:                    return "true";
    }
}

static const char *policy_object_target_str(enum pa_policy_object_target target)
{
    switch (target) {
        case pa_object_name:                    return "(name)";
        case pa_object_property:                return "(property)";
        case pa_object_string:                  return "(string)";
        default: pa_assert_not_reached(); break;
    }

    return NULL;
}

pa_policy_match_object *policy_match_new(enum pa_classify_method method,
                                         const char *string)
{
    pa_policy_match_object *obj = NULL;

    obj = pa_xnew0(pa_policy_match_object, 1);
    obj->arg_def = string ? pa_xstrdup(string) : NULL;

    switch (method) {
        case pa_method_equals:
            obj->func = pa_classify_method_equals;
            obj->arg.string = obj->arg_def;
            break;

        case pa_method_startswith:
            obj->func = pa_classify_method_startswith;
            obj->arg.string = obj->arg_def;
            break;

        case pa_method_matches:
            obj->func = pa_classify_method_matches;
            if (regcomp(&obj->arg.rexp, obj->arg_def, 0) != 0) {
                pa_log("failed to compile regex from '%s'", obj->arg_def);
                goto fail;
            }
            break;

        case pa_method_true:
            obj->func = pa_classify_method_true;
            break;

        default:
            pa_log("bad method type %d", method);
            pa_assert_not_reached();
            goto fail;
    }

    obj->method = method;
    obj->type   = pa_policy_object_unknown;

    return obj;

fail:
    pa_policy_match_free(obj);
    return NULL;
}

pa_policy_match_object *pa_policy_match_string_new(enum pa_classify_method method,
                                                   const char *string)
{
    pa_policy_match_object *obj = NULL;

    if (!(obj = policy_match_new(method, string)))
        return NULL;

    obj->target = pa_object_string;

#ifdef DEBUG_MATCH
    pa_log_debug("new %s match %s:%s", policy_object_target_str(obj->target),
                                       method_str(method),
                                       string ? string : "<none>");
#endif

    return obj;
}

pa_policy_match_object *pa_policy_match_name_new(enum pa_policy_object_type type,
                                                 enum pa_classify_method method,
                                                 const char *string)
{
    pa_policy_match_object *obj = NULL;

    if (!(obj = policy_match_new(method, string)))
        return NULL;

    obj->type   = type;
    obj->target = pa_object_name;

#ifdef DEBUG_MATCH
    pa_log_debug("new %s match %s:%s", policy_object_target_str(obj->target),
                                       method_str(method),
                                       string ? string : "<none>");
#endif

    return obj;
}

pa_policy_match_object *pa_policy_match_property_new(enum pa_policy_object_type type,
                                                     const char *property_name,
                                                     enum pa_classify_method method,
                                                     const char *string)
{
    pa_policy_match_object *obj = NULL;

    pa_assert(property_name);

    if (!(obj = policy_match_new(method, string)))
        return NULL;

    obj->type       = type;
    obj->target     = pa_object_property;
    obj->target_def = pa_xstrdup(property_name);
    obj->method     = method;

#ifdef DEBUG_MATCH
    pa_log_debug("new %s match %s %s:%s", policy_object_target_str(obj->target),
                                          obj->target_def,
                                          method_str(method),
                                          string ? string : "<none>");
#endif

    return obj;
}

pa_policy_match_object *pa_policy_match_new(enum pa_policy_object_type type,
                                            enum pa_policy_object_target target,
                                            const char *target_def,
                                            enum pa_classify_method method,
                                            const char *arg)
{
    pa_policy_match_object *obj = NULL;

    pa_assert(method == pa_method_true || arg);

    if (type == pa_policy_object_proplist &&
        target != pa_object_property) {
        pa_log("invalid type for proplist match object.");
        goto fail;
    }

    if (!(obj = policy_match_new(method, arg)))
        goto fail;

    obj->type           = type;
    obj->target         = target;
    obj->target_def     = pa_xstrdup(target_def);
    obj->method         = method;

#ifdef DEBUG_MATCH
    pa_log_debug("new match: %s %s%s:%s %s", pa_policy_object_type_str(type),
                                             policy_object_target_str(target),
                                             target == pa_object_property ? target_def : "",
                                             method_str(method),
                                             arg ? arg : "<none>");
#endif

    return obj;

fail:
    pa_policy_match_free(obj);
    return NULL;
}

void pa_policy_match_free(pa_policy_match_object *obj)
{
    if (!obj)
        return;

    if (obj->method == pa_method_matches)
        regfree(&obj->arg.rexp);

    pa_xfree(obj->arg_def);
    pa_xfree(obj->target_def);
    pa_xfree(obj);
}

const char *object_name(enum pa_policy_object_type obj_type, const void *obj)
{
    pa_assert(obj);

    switch (obj_type) {
        case pa_policy_object_module:       return ((const pa_module *) obj)->name;
        case pa_policy_object_card:         return ((const pa_card *) obj)->name;
        case pa_policy_object_sink:         return ((const pa_sink *) obj)->name;
        case pa_policy_object_source:       return ((const pa_source *) obj)->name;
        case pa_policy_object_sink_input:   return pa_proplist_gets(((const pa_sink_input *) obj)->proplist,
                                                                    PA_PROP_MEDIA_NAME);
        case pa_policy_object_source_output:return pa_proplist_gets(((const pa_source_output *) obj)->proplist,
                                                                    PA_PROP_MEDIA_NAME);
        case pa_policy_object_port:         return ((const pa_device_port *) obj)->name;
        case pa_policy_object_profile:      return ((const pa_card_profile *) obj)->name;
        case pa_policy_object_proplist:     return "<<proplist>>";
        default: pa_assert_not_reached();   return NULL;
    }

    return NULL;
}

const char *object_proplist_get(pa_policy_match_object *obj,
                                const void *target)
{
    switch (obj->type) {
        case pa_policy_object_module:
            return pa_proplist_gets(((const pa_module *) target)->proplist, obj->target_def);

        case pa_policy_object_card:
            return pa_proplist_gets(((const pa_card *) target)->proplist, obj->target_def);

        case pa_policy_object_sink:
            return pa_proplist_gets(((const pa_sink *) target)->proplist, obj->target_def);

        case pa_policy_object_source:
            return pa_proplist_gets(((const pa_source *) target)->proplist, obj->target_def);

        case pa_policy_object_sink_input:
            return pa_proplist_gets(((const pa_sink_input *) target)->proplist, obj->target_def);

        case pa_policy_object_source_output:
            return pa_proplist_gets(((const pa_source_output *) target)->proplist, obj->target_def);

        case pa_policy_object_port:
            return pa_proplist_gets(((const pa_device_port *) target)->proplist, obj->target_def);

        /* card profile doesn't have proplist */
        case pa_policy_object_profile:
            return NULL;

        case pa_policy_object_proplist:
            return pa_proplist_gets((pa_proplist *) target, obj->target_def);

        default:
            pa_assert_not_reached();
    }

    return NULL;
}

static bool policy_match(pa_policy_match_object *obj, const void *target, const char *to_check)
{
    bool match = false;

    pa_assert(obj);

    if (to_check)
        match = obj->func(to_check, &obj->arg);

#ifdef DEBUG_MATCH
    if (obj->target == pa_object_string)
        pa_log_debug("match string '%s' %s '%s' = %s",
                     obj->arg_def ? obj->arg_def : "",
                     method_str(obj->method),
                     to_check ? to_check : "",
                     match ? "True" : "False");
    else if (obj->target == pa_object_name)
        pa_log_debug("match %s '%s' name %s '%s' = %s",
                     pa_policy_object_type_str(obj->type),
                     to_check,
                     method_str(obj->method),
                     obj->arg_def ? obj->arg_def : "",
                     match ? "True" : "False");
    else if (obj->target == pa_object_property)
        pa_log_debug("match %s '%s' property '%s' value '%s' %s '%s' = %s",
                     pa_policy_object_type_str(obj->type),
                     object_name(obj->type, target),
                     obj->target_def,
                     to_check,
                     method_str(obj->method),
                     obj->arg_def ? obj->arg_def : "",
                     match ? "True" : "False");
#endif

    return match;
}

bool pa_policy_match_type(pa_policy_match_object *obj,
                          enum pa_policy_object_type expected_type,
                          const void *target)
{
    pa_assert(obj);

#ifdef DEBUG_MATCH
    pa_log_debug("match object type is %s, expected %s (%s)",
                 pa_policy_object_type_str(obj->type),
                 pa_policy_object_type_str(expected_type),
                 object_name(expected_type, target));
#endif

    if (obj->type != expected_type)
        return false;

    return pa_policy_match(obj, target);
}

bool pa_policy_match(pa_policy_match_object *obj, const void *target)
{
    const char *to_check = NULL;

    pa_assert(obj);
    pa_assert(obj->func);

    if (!target)
        return false;

    switch (obj->target) {
        case pa_object_string:  to_check = target; break;
        case pa_object_name:    to_check = object_name(obj->type, target); break;
        case pa_object_property:to_check = object_proplist_get(obj, target); break;
        default:
            pa_assert_not_reached();
            return false;
    }

    return policy_match(obj, target, to_check);
}

char *pa_policy_match_def(pa_policy_match_object *obj)
{
    pa_assert(obj);

    if (obj->target == pa_object_string)
        return pa_sprintf_malloc("(string) %s:%s", method_str(obj->method),
                                                   obj->arg_def);
    else if (obj->target == pa_object_name)
        return pa_sprintf_malloc("(%s name) %s:%s", policy_object_target_str(obj->target),
                                                    method_str(obj->method),
                                                    obj->arg_def);
    else if (obj->target == pa_object_property)
        return pa_sprintf_malloc("(property) %s %s:%s", obj->target_def,
                                                        method_str(obj->method),
                                                        obj->arg_def);

    return NULL;
}

const char *pa_policy_match_arg(pa_policy_match_object *obj)
{
    pa_assert(obj);

    return obj->arg_def;
}

enum pa_classify_method pa_policy_match_method(pa_policy_match_object *obj)
{
    pa_assert(obj);

    return obj->method;
}

const char *pa_match_method_str(enum pa_classify_method method)
{
    return method_str(method);
}

int pa_classify_method_equals(const char *string,
                              union pa_classify_arg *arg)
{
    int found;

    if (!string || !arg || !arg->string)
        found = false;
    else
        found = !strcmp(string, arg->string);

    return found;
}

int pa_classify_method_startswith(const char *string,
                                  union pa_classify_arg *arg)
{
    int found;

    if (!string || !arg || !arg->string)
        found = false;
    else
        found = !strncmp(string, arg->string, strlen(arg->string));

    return found;
}

int pa_classify_method_matches(const char *string,
                               union pa_classify_arg *arg)
{
#define MAX_MATCH 5

    regmatch_t m[MAX_MATCH];
    regoff_t   end;
    int        found;

    found = false;

    if (string && arg) {
        if (regexec(&arg->rexp, string, MAX_MATCH, m, 0) == 0) {
            end = strlen(string);

            if (m[0].rm_so == 0 && m[0].rm_eo == end && m[1].rm_so == -1)
                found = true;
        }
    }


    return found;

#undef MAX_MATCH
}

int pa_classify_method_true(const char *string,
                            union pa_classify_arg *arg)
{
    (void)string;
    (void)arg;

    return true;
}
