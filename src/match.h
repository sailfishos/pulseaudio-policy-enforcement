#ifndef foopolicymatchfoo
#define foopolicymatchfoo

#include <stdbool.h>
#include <regex.h>

enum pa_policy_object_type {
    pa_policy_object_unknown = 0,
    pa_policy_object_min = pa_policy_object_unknown,

    pa_policy_object_module,
    pa_policy_object_card,
    pa_policy_object_sink,
    pa_policy_object_source,
    pa_policy_object_sink_input,
    pa_policy_object_source_output,
    pa_policy_object_port,              /* sink/source port */
    pa_policy_object_profile,           /* card profile */
    pa_policy_object_proplist,

    pa_policy_object_max
};

enum pa_classify_method {
    pa_method_unknown = 0,
    pa_method_min = pa_method_unknown,
    pa_method_equals,
    pa_method_startswith,
    pa_method_matches,
    pa_method_true,
    pa_method_max
};

enum pa_policy_object_target {
    pa_object_unknown,
    pa_object_name,
    pa_object_property,
    pa_object_string,
    pa_object_max
};

union pa_classify_arg {
    char       *string;
    regex_t     rexp;
};

struct pa_policy_match_object {
    enum pa_policy_object_type      type;
    enum pa_policy_object_target    target;
    char                           *target_def; /* NULL for pa_object_name */
    enum pa_classify_method         method;
    int                           (*func)(const char *, union pa_classify_arg *);
    union pa_classify_arg           arg;
    char                           *arg_def;
};

typedef struct pa_policy_match_object pa_policy_match_object;

pa_policy_match_object *pa_policy_match_string_new(enum pa_classify_method method,
                                                   const char *string);
pa_policy_match_object *pa_policy_match_name_new(enum pa_policy_object_type type,
                                                 enum pa_classify_method method,
                                                 const char *arg);
pa_policy_match_object *pa_policy_match_property_new(enum pa_policy_object_type type,
                                                     const char *property_name,
                                                     enum pa_classify_method method,
                                                     const char *arg);
pa_policy_match_object *pa_policy_match_new(enum pa_policy_object_type type,
                                            enum pa_policy_object_target target,
                                            const char *target_def,
                                            enum pa_classify_method method,
                                            const char *arg);
void pa_policy_match_free(pa_policy_match_object *obj);
bool pa_policy_match(pa_policy_match_object *obj, const void *target);
bool pa_policy_match_type(pa_policy_match_object *obj,
                          enum pa_policy_object_type expected_type,
                          const void *target);

char *pa_policy_match_def(pa_policy_match_object *obj);
const char *pa_policy_match_arg(pa_policy_match_object *obj);
enum pa_classify_method pa_policy_match_method(pa_policy_match_object *obj);

const char *pa_match_method_str(enum pa_classify_method method);
int   pa_classify_method_equals(const char *, union pa_classify_arg *);
int   pa_classify_method_startswith(const char *, union pa_classify_arg *);
int   pa_classify_method_matches(const char *, union pa_classify_arg *);
int   pa_classify_method_true(const char *, union pa_classify_arg *);

const char *pa_policy_object_type_str(enum pa_policy_object_type obj_type);

#endif
