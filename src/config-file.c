
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>

#ifndef __USE_ISOC99
#define __USE_ISOC99
#include <ctype.h>
#undef __USE_ISOC99
#else
#include <ctype.h>
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulsecore/core-util.h>
#include <pulsecore/llist.h>
#include <pulsecore/log.h>

#include "config-file.h"
#include "policy-group.h"
#include "classify.h"
#include "context.h"
#include "variable.h"

#ifndef PA_DEFAULT_CONFIG_DIR
#define PA_DEFAULT_CONFIG_DIR "/etc/pulse"
#endif

#define DEFAULT_CONFIG_FILE        "xpolicy.conf"
#define DEFAULT_CONFIG_DIRECTORY   "/etc/pulse/xpolicy.conf.d"

#define DEFAULT_PORT_CHANGE_DELAY_MS (200)

enum section_type {
    section_unknown = 0,
    section_group,
    section_device,
    section_card,
    section_stream,
    section_context,
    section_activity,
    section_variable,
    section_max
};

enum device_class {
    device_unknown = 0,
    device_sink,
    device_source,
    device_max
};


#define PROPERTY_ACTION_COMMON                                                \
    enum pa_policy_object_type objtype; /* eg. sink, source, sink-input etc */\
    enum pa_classify_method    method;  /* obj.name based classif. method   */\
    char                      *arg;     /* obj.name based classif. argument */\
    char                      *propnam  /* name of property                 */

struct anyprop {
    PROPERTY_ACTION_COMMON;
};

struct setprop {                         /* set property of a PA object */
    PROPERTY_ACTION_COMMON;
    enum pa_policy_value_type  valtype;  /* type of prop.value to be set */
    char                      *valarg;   /* arg for value setting, if any */
};

struct delprop {                         /* delete property of a PA object */
    PROPERTY_ACTION_COMMON;
};

struct setdef {
    PROPERTY_ACTION_COMMON;
    char *activity_group;
    int default_state;                   /* default state for activity, used
                                            when activity ends */
};


struct ctxact {                          /* context rule actions */
    enum pa_policy_action_type type;     /* context action type */
    int                        lineno;   /* reference to config file */
    union {
        struct anyprop         anyprop;  /* common for all prop.operation */
        struct setprop         setprop;  /* setting property of an object */
        struct delprop         delprop;  /* deleting property of an object */
        struct setdef          setdef;   /* setting default value for activity */
    };
};


struct groupdef {
    char                    *name;
    char                    *sink;
    enum pa_classify_method  sink_method;
    char                    *sink_prop;
    char                    *sink_arg;
    char                    *source;
    enum pa_classify_method  source_method;
    char                    *source_prop;
    char                    *source_arg;
    pa_proplist             *properties;
    char                    *flags;
    int                      flags_lineno;
};

struct devicedef {
    enum device_class        class;
    char                    *type;
    char                    *prop;
    enum pa_classify_method  method;
    char                    *arg;
    pa_hashmap              *ports; /* Key: device name, value:
                                     * pa_classify_port_entry. */
    char                    *module;
    char                    *module_args;
    char                    *delay;
    int                      delay_lineno;
    char                    *flags;
    int                      flags_lineno;
};

struct carddef {
    char                    *type;
    enum pa_classify_method  method[2];
    char                    *arg[2];
    char                    *profile[2];
    char                    *flags[2];
    int                      flags_lineno[2];
};

struct streamdef {
    char                    *prop;   /* stream property to classify it */
    enum pa_classify_method  method; /* property based classification method */
    char                    *arg;    /* param for prop.based classification */
    char                    *clnam;  /* client's name in pulse audio */
    char                    *sname;  /* active sink target */
    uid_t                    uid;    /* client's user id */
    char                    *exe;    /* the executable name (i.e. argv[0]) */
    char                    *group;  /* group name the stream belong to */
    char                    *flags;  /* stream flags */
    int                      flags_lineno;
    char                    *port;   /* port for local routing, if any */
};


struct contextdef {
    char                    *varnam; /* context variable name */
    enum pa_classify_method  method; /* context value based classification */
    char                    *arg;    /* param for ctx.value classification */
    int                      nact;   /* number of actions */
    struct ctxact           *acts;   /* array of actions */
};

struct activitydef {
    char                    *device; /* device route name */
    enum pa_classify_method  method; /* sink name based classification */
    char                    *name;   /* sink name */
    int                      active_nact;   /* number of actions when changing to active state */
    struct ctxact           *active_acts;   /* array of actions when changing to active state */
    int                      inactive_nact; /* number of actions when changing to inactive state */
    struct ctxact           *inactive_acts; /* array of actions when changing to inactive state */
};

struct section {
    enum section_type        type;
    union {
        void              *any;
        struct groupdef   *group;
        struct devicedef  *device;
        struct carddef    *card;
        struct streamdef  *stream;
        struct contextdef *context;
        struct activitydef *activity;
    }                        def;

    PA_LLIST_FIELDS(struct section);
};

struct sections {
    PA_LLIST_HEAD(struct section, sec);
};


static int parse_line(struct userdata *u, int lineno, char *buf, struct sections *sections, int *success);
static int preprocess_buffer(int, char *, char *);

static int section_header(int, char *, enum section_type *);
static int section_open(struct userdata *, enum section_type,struct section *);
static int section_close(struct userdata *, struct section *);
static int section_close_all(struct userdata *u, struct sections *sections);

static int groupdef_parse(int, char *, struct groupdef *);
static int devicedef_parse(int, char *, struct devicedef *);
static int carddef_parse(int, char *, struct carddef *);
static int streamdef_parse(int, char *, struct streamdef *);
static int contextdef_parse(int, char *, struct contextdef *);
static int activitydef_parse(int, char *, struct activitydef *);
static int variabledef_parse(int lineno, char *line, char **ret_var, char **ret_value);

static int method_parse(int lineno, char *definition,
                        enum pa_classify_method *method_val,
                        char **method_prop,
                        char **method_arg);
static int ports_parse(int, const char *, struct devicedef *);
static int module_parse(int, const char *, struct devicedef *);
static int streamprop_parse(int, char *, struct streamdef *);
static int contextval_parse(int, char *, enum pa_classify_method *method, char **arg);
static int contextsetprop_parse(int, char *, int *nact, struct ctxact **acts);
static int contextdelprop_parse(int, char *, int *nact, struct ctxact **acts);
static int contextsetdef_parse(int lineno, char *setdefdef, int *nact, struct ctxact **acts);
static int contextoverride_parse(int lineno, char *setdefdef, int *nact, struct ctxact **acts);
static int contextanyprop_parse(int, char *, char *, struct anyprop *);
static int cardname_parse(int, char *, struct carddef *, int field);
static int flags_parse(struct userdata *u, int, const char *, enum section_type, uint32_t *);
static void delay_parse(struct userdata *u, int, const char *, uint32_t *);
static int valid_label(int, char *);
const char *policy_file_path(const char *file, char *buf, size_t len);

static char **split_strv(const char *s, const char *delimiter);

static int policy_parse_config_file(struct userdata *u, const char *cfgfile, struct sections *sections);
static int policy_parse_files_in_configdir(struct userdata *u, const char *cfgdir, struct sections *sections);

int pa_policy_parse_config_files(struct userdata *u, const char *cfgfile, const char *cfgdir)
{
    struct sections sections;
    int             ret;

    memset(&sections, 0, sizeof(sections));
    PA_LLIST_HEAD_INIT(struct section, sections.sec);

    ret = policy_parse_config_file(u, cfgfile, &sections);
    if (ret)
        ret = policy_parse_files_in_configdir(u, cfgdir, &sections);
    if (ret)
        ret = section_close_all(u, &sections);
    if (ret)
        pa_log_debug("all configs parsed");

    return ret;
}

int policy_parse_config_file(struct userdata *u, const char *cfgfile, struct sections *sections)
{
#define BUFSIZE 512

    FILE              *f;
    char               cfgpath[PATH_MAX];
    char               ovrpath[PATH_MAX];
    char              *path;
    char               buf[BUFSIZE];
    int                lineno;
    int                success;

    pa_assert(u);

    if (!cfgfile)
        cfgfile = DEFAULT_CONFIG_FILE;

    policy_file_path(cfgfile, cfgpath, PATH_MAX);
    snprintf(ovrpath, PATH_MAX, "%s.override", cfgpath);

    if ((f = fopen(ovrpath,"r")) != NULL)
        path = ovrpath;
    else if ((f = fopen(cfgpath, "r")) != NULL)
        path = cfgpath;
    else {
        pa_log("Can't open config file '%s': %s", cfgpath, strerror(errno));
        return 0;
    }

    pa_log_info("parsing config file '%s'", path);

    success = true;                    /* assume successful operation */

    for (errno = 0, lineno = 1;  fgets(buf, BUFSIZE, f) != NULL;  lineno++) {
        if (!parse_line(u, lineno, buf, sections, &success))
            break;
    }

    if (fclose(f) != 0) {
        pa_log("Can't close config file '%s': %s", path, strerror(errno));
    }

    return success;
}

int policy_parse_files_in_configdir(struct userdata *u, const char *cfgdir, struct sections *sections)
{
#define BUFSIZE 512

    pa_dynarray       *files = NULL;
    DIR               *d;
    FILE              *f;
    struct dirent     *e;
    const char        *p;
    char              *q;
    int                l;
    char               cfgpath[PATH_MAX];
    char             **overrides;
    unsigned           noverride;
    char               buf[BUFSIZE];
    int                lineno;
    unsigned           i, j;
    int                success;

    pa_assert(u);

    if (!cfgdir)
        cfgdir = DEFAULT_CONFIG_DIRECTORY;

    pa_log_info("policy config directory is '%s'", cfgdir);

    success = 1;
    overrides = NULL;
    noverride = 0;

    if ((d = opendir(cfgdir)) != NULL) {
        while ((e = readdir(d)) != NULL) {
            if ((p = strstr(e->d_name, ".conf.override")) == NULL || p[14])
                continue;       /* does not match '*.conf.override' */

            l = (p + 5) - e->d_name; /* length of '*.conf' */
            q = pa_xmalloc(l + 1);
            strncpy(q, e->d_name, l);
            q[l] = '\0';

            overrides = pa_xrealloc(overrides, (noverride+1) * sizeof(char *));
            overrides[noverride++] = q;
        }
        closedir(d);
    }

    if ((d = opendir(cfgdir)) == NULL)
        pa_log_info("Can't find config directory '%s'", cfgdir);
    else {
        files = pa_dynarray_new(NULL);

        for (p = cfgdir, q = cfgpath;  (q-cfgpath < PATH_MAX) && *p;   p++,q++)
            *q = *p;
        if (q == cfgpath || q[-1] != '/')
            *q++ = '/'; 
        l = (cfgpath + PATH_MAX) - q;

        while (l > 1 && (e = readdir(d)) != NULL) {
            if ((p = strstr(e->d_name, ".conf")) != NULL && !p[5]) {
                for (i = 0;  i < noverride; i++) {
                    if (!strcmp(e->d_name, overrides[i]))
                        break;
                }

                if (i < noverride) {
                    strncpy(q, e->d_name, l);
                    cfgpath[PATH_MAX-1] = '\0';
                    pa_log_info("skip overriden config file '%s'", cfgpath);
                    continue;
                }
            }
            else if ((p = strstr(e->d_name,".conf.override")) == NULL || p[14])
                continue;       /* neither '*.conf' nor '*.conf.override' */

            strncpy(q, e->d_name, l);
            cfgpath[PATH_MAX-1] = '\0';

            pa_dynarray_append(files, pa_xstrdup(cfgpath));

        } /* while readdir() */

        closedir(d);

    } /* if opendir() */

    /* read config files in descending order */
    if (files) {
        char **sorted_files;
        unsigned count;

        errno = 0;

        count = pa_dynarray_size(files);
        sorted_files = pa_xnew(char *, count);

        for (i = 0; i < count; i++)
            sorted_files[i] = pa_dynarray_get(files, i);
        pa_dynarray_free(files);

        for (i = 0; i < count; i++) {
            for (j = 0; j < count; j++) {
                if (strcmp(sorted_files[i], sorted_files[j]) < 0) {
                    char *tmp = sorted_files[i];
                    sorted_files[i] = sorted_files[j];
                    sorted_files[j] = tmp;
                }
            }
        }

        for (i = 0; i < count; i++) {
            pa_log_info("parsing config file '%s'", sorted_files[i]);

            if ((f = fopen(sorted_files[i], "r")) == NULL) {
                pa_log("Can't open config file '%s': %s",
                        sorted_files[i], strerror(errno));
                continue;
            }

            for (errno = 0, lineno = 1;  fgets(buf, BUFSIZE, f);   lineno++) {
                if (!parse_line(u, lineno, buf, sections, &success))
                    break;
            }

            if (fclose(f) != 0) {
                pa_log("Can't close config file '%s': %s",
                        sorted_files[i], strerror(errno));
            }

            pa_xfree(sorted_files[i]);
        }

        pa_xfree(sorted_files);
    }

    for (i = 0; i < noverride; i++)
        pa_xfree(overrides[i]);

    pa_xfree(overrides);

    return success;
}

static int parse_line(struct userdata *u, int lineno, char *buf, struct sections *sections, int *success) {
    struct section     *section;
    enum section_type   newsect;
    struct groupdef    *grdef;
    struct devicedef   *devdef;
    struct carddef     *carddef;
    struct streamdef   *strdef;
    struct contextdef  *ctxdef;
    struct activitydef *actdef;
    char                line[BUFSIZE];

    if (preprocess_buffer(lineno, buf, line) < 0)
        return 0;

    if (*line == '\0')
        return 1;

    if (section_header(lineno, line, &newsect)) {
        section = pa_xnew0(struct section, 1);
        PA_LLIST_INIT(struct section, section);
        section->type = newsect;

        PA_LLIST_PREPEND(struct section, sections->sec, section);

        if (section_open(u, newsect, section) < 0)
            *success = 0;
    }
    else {
        pa_assert_se((section = sections->sec));

        switch (section->type) {

        case section_group:
            grdef = section->def.group;

            if (groupdef_parse(lineno, line, grdef) < 0)
                *success = 0;

            break;

        case section_device:
            devdef = section->def.device;

            if (devicedef_parse(lineno, line, devdef) < 0)
                *success = 0;

            break;

        case section_card:
            carddef = section->def.card;

            if (carddef_parse(lineno, line, carddef) < 0)
                *success = 0;

            break;

        case section_stream:
            strdef = section->def.stream;

            if (streamdef_parse(lineno, line, strdef) < 0)
                *success = 0;

            break;

        case section_context:
            ctxdef = section->def.context;

            if (contextdef_parse(lineno, line, ctxdef) < 0)
                *success = 0;

            break;

        case section_activity:
            actdef = section->def.activity;

            if (activitydef_parse(lineno, line, actdef) < 0)
                *success = 0;

            break;

        case section_variable: {
            char *var;
            char *value;

            if (variabledef_parse(lineno, line, &var, &value) < 0)
                *success = 0;
            else {
                pa_policy_var_add(u, var, value);
                pa_xfree(var);
                pa_xfree(value);
            }

            break;
        }

        default:
            break;

        }
    }

    return 1;
}

static int preprocess_buffer(int lineno, char *inbuf, char *outbuf)
{
    char c, *p, *q;
    int  quote;
    int  sts = 0;

    for (quote = 0, p = inbuf, q = outbuf;   (c = *p) != '\0';   p++) {
        if (!quote && isblank(c))
            continue;
        
        if (c == '\n' || (!quote && c == '#'))
            break;
        
        if (c == '"') {
            quote ^= 1;
            continue;
        }
        
        if (c < 0x20) {
            pa_log("Illegal character 0x%02x in line %d", c, lineno);
            sts = -1;
            errno = EILSEQ;
            break;
        }
        
        *q++ = c;
    }
    *q = '\0';

    if (quote) {
        pa_log("unterminated quoted string '%s' in line %d", inbuf, lineno);
    }

    return sts;
}


static int section_header(int lineno, char *line, enum section_type *type)
{
    int is_section;

    if (line[0] != '[')
        is_section = 0;
    else {
        is_section = 1;

        if (!strcmp(line, "[group]"))
            *type = section_group;
        else if (!strcmp(line,"[device]"))
            *type = section_device;
        else if (!strcmp(line,"[card]"))
            *type = section_card;
        else if (!strcmp(line, "[stream]"))
            *type = section_stream;
        else if (!strcmp(line, "[context-rule]"))
            *type = section_context;
        else if (!strcmp(line, "[activity]"))
            *type = section_activity;
        else if (!strcmp(line, "[variable]"))
            *type = section_variable;
        else {
            *type = section_unknown;
            pa_log("Invalid section type '%s' in line %d", line, lineno);
        }
    }

    return is_section;
}

static int section_open(struct userdata *u, enum section_type type,
                        struct section *sec)
{
    int status;

    if (sec == NULL)
        status = -1;
    else {
        switch (type) {
            
        case section_group:
            sec->def.group = pa_xnew0(struct groupdef, 1);
            status = 0;
            break;
            
        case section_device:
            sec->def.device = pa_xnew0(struct devicedef, 1);
            status = 0;
            break;

        case section_card:
            sec->def.card = pa_xnew0(struct carddef, 1);
            status = 0;
            break;

        case section_stream:
            sec->def.stream = pa_xnew0(struct streamdef, 1);
            sec->def.stream->uid = -1;
            status = 0;
            break;

        case section_context:
            sec->def.context = pa_xnew0(struct contextdef, 1);
            sec->def.context->method = pa_method_true;
            status = 0;
            break;

        case section_activity:
            sec->def.activity = pa_xnew0(struct activitydef, 1);
            sec->def.activity->method = pa_method_true;
            status = 0;
            break;

        case section_variable:
            status = 0;
            break;

        default:
            type = section_unknown;
            sec->def.any = NULL;
            status = -1;
            break;
        }

        sec->type = type;
    }

    return status;
}

static int section_close_all(struct userdata *u, struct sections *sections)
{
    struct section *section, *tmp, *reverse;
    int ret = 1;

    PA_LLIST_HEAD_INIT(struct section, reverse);

    /* As the sections are read from configuration files backwards,
     * we need to reverse the order when closing the sections.
     */
    PA_LLIST_FOREACH_SAFE(section, tmp, sections->sec) {
        PA_LLIST_REMOVE(struct section, sections->sec, section);
        PA_LLIST_PREPEND(struct section, reverse, section);
    }

    PA_LLIST_FOREACH_SAFE(section, tmp, reverse) {
        ret = section_close(u, section);
        pa_xfree(section);
        if (ret == 0)
            goto done;
    }

done:
    return ret;
}

static void section_free(struct section *sec) {
    struct ctxact      *act;
    struct setprop     *setprop;
    struct delprop     *delprop;
    struct setdef      *setdef;
    int                 i;

    switch (sec->type) {
        case section_group:
            pa_xfree(sec->def.group->name);
            pa_xfree(sec->def.group->sink);
            pa_xfree(sec->def.group->sink_prop);
            pa_xfree(sec->def.group->sink_arg);
            pa_xfree(sec->def.group->source);
            pa_xfree(sec->def.group->source_prop);
            pa_xfree(sec->def.group->source_arg);
            pa_xfree(sec->def.group->flags);
            pa_xfree(sec->def.group);
            break;

        case section_device:
            if (sec->def.device->ports)
                pa_hashmap_free(sec->def.device->ports);
            pa_xfree(sec->def.device->type);
            pa_xfree(sec->def.device->prop);
            pa_xfree(sec->def.device->arg);
            pa_xfree(sec->def.device->module);
            pa_xfree(sec->def.device->module_args);
            pa_xfree(sec->def.device->flags);
            pa_xfree(sec->def.device->delay);
            pa_xfree(sec->def.device);
            break;

        case section_card:
            pa_xfree(sec->def.card->type);
            for (i = 0; i < PA_POLICY_CARD_MAX_DEFS; i++) {
                pa_xfree(sec->def.card->arg[i]);
                pa_xfree(sec->def.card->profile[i]);
                pa_xfree(sec->def.card->flags[i]);
            }
            pa_xfree(sec->def.card);
            break;

        case section_stream:
            pa_xfree(sec->def.stream->prop);
            pa_xfree(sec->def.stream->arg);
            pa_xfree(sec->def.stream->clnam);
            pa_xfree(sec->def.stream->sname);
            pa_xfree(sec->def.stream->exe);
            pa_xfree(sec->def.stream->group);
            pa_xfree(sec->def.stream->port);
            pa_xfree(sec->def.stream);
            break;

        case section_context:
            for (i = 0; i < sec->def.context->nact; i++) {
                act = sec->def.context->acts + i;
                switch (act->type) {
                    case pa_policy_set_property:
                        setprop = &act->setprop;
                        pa_xfree(setprop->arg);
                        pa_xfree(setprop->propnam);
                        pa_xfree(setprop->valarg);
                        break;

                    case pa_policy_delete_property:
                        delprop = &act->delprop;
                        pa_xfree(delprop->arg);
                        pa_xfree(delprop->propnam);
                        break;

                    case pa_policy_set_default:
                        setdef = &act->setdef;
                        pa_xfree(setdef->activity_group);
                        break;

                    case pa_policy_override:
                        setprop = &act->setprop;
                        pa_xfree(setprop->arg);
                        pa_xfree(setprop->propnam);
                        pa_xfree(setprop->valarg);
                        break;

                    default:
                        break;
                }
            }
            pa_xfree(sec->def.context->varnam);
            pa_xfree(sec->def.context->arg);
            pa_xfree(sec->def.context->acts);
            pa_xfree(sec->def.context);
            break;

        case section_activity:
            for (i = 0; i < sec->def.activity->active_nact; i++) {
                act = sec->def.activity->active_acts + i;
                switch (act->type) {
                    case pa_policy_set_property:
                        setprop = &act->setprop;
                        pa_xfree(setprop->arg);
                        pa_xfree(setprop->propnam);
                        pa_xfree(setprop->valarg);
                        break;
                    default:
                        break;
                }
            }
            for (i = 0; i < sec->def.activity->inactive_nact; i++) {
                act = sec->def.activity->inactive_acts + i;
                switch (act->type) {
                    case pa_policy_set_property:
                        setprop = &act->setprop;
                        pa_xfree(setprop->arg);
                        pa_xfree(setprop->propnam);
                        pa_xfree(setprop->valarg);
                        break;
                    default:
                        break;
                }
            }
            pa_xfree(sec->def.activity->name);
            pa_xfree(sec->def.activity->active_acts);
            pa_xfree(sec->def.activity->inactive_acts);
            pa_xfree(sec->def.activity);
            break;

        case section_variable:
            break;

        default:
            break;
    }
}

static int section_close(struct userdata *u, struct section *sec)
{
    struct groupdef   *grdef;
    struct devicedef  *devdef;
    struct carddef    *carddef;
    struct streamdef  *strdef;
    struct contextdef *ctxdef;
    struct activitydef *actdef;
    struct ctxact     *act;
    struct pa_policy_context_rule *rule;
    struct setprop    *setprop;
    struct delprop    *delprop;
    struct setdef     *setdef;
    uint32_t           delay = DEFAULT_PORT_CHANGE_DELAY_MS;
    uint32_t           card_flags[2] = { 0, 0};
    uint32_t           flags = 0;
    int                status = 0;
    int                i;

    if (sec == NULL)
        status = 0;
    else {
        switch (sec->type) {

        case section_group:
            status = 1;
            grdef  = sec->def.group;

            flags_parse(u, grdef->flags_lineno, grdef->flags, section_group, &flags);

            /* Transfer ownership of grdef->properties */
            pa_policy_group_new(u, grdef->name,   grdef->sink,
                                   grdef->sink_method, grdef->sink_arg, grdef->sink_prop,
                                   grdef->source,
                                   grdef->source_method, grdef->source_arg, grdef->source_prop,
                                   grdef->properties,
                                   flags);
            break;

        case section_device:
            status = 1;
            devdef = sec->def.device;

            flags_parse(u, devdef->flags_lineno, devdef->flags, section_device, &flags);
            delay_parse(u, devdef->delay_lineno, devdef->delay, &delay);

            switch (devdef->class) {

            case device_sink:
                /* All devdef values are deep copied. */
                pa_classify_add_sink(u, devdef->type,
                                     devdef->prop, devdef->method, devdef->arg,
                                     devdef->ports,
                                     devdef->module, devdef->module_args,
                                     flags, delay);
                break;

            case device_source:
                /* All devdef values are deep copied. */
                pa_classify_add_source(u, devdef->type,
                                       devdef->prop, devdef->method,
                                       devdef->arg, devdef->ports,
                                       devdef->module, devdef->module_args,
                                       flags);
                break;

            default:
                break;
            }

            break;

        case section_card:
            status = 1;
            carddef = sec->def.card;

            for (i = 0; i < PA_POLICY_CARD_MAX_DEFS; i++)
                flags_parse(u, carddef->flags_lineno[i], carddef->flags[i], section_card, &card_flags[i]);

            pa_classify_add_card(u, carddef->type, carddef->method,
                                 carddef->arg, carddef->profile,
                                 card_flags);


            break;

        case section_stream:
            status = 1;
            strdef = sec->def.stream;

            flags_parse(u, strdef->flags_lineno, strdef->flags, section_stream, &flags);

            if (strdef->port)
                flags |= PA_POLICY_LOCAL_ROUTE;

            pa_classify_add_stream(u, strdef->prop,strdef->method,strdef->arg,
                                   strdef->clnam, strdef->sname, strdef->uid, strdef->exe,
                                   strdef->group, flags, strdef->port);

            break;

        case section_context:
            status = 1;
            ctxdef = sec->def.context;

            rule = pa_policy_context_add_property_rule(u, ctxdef->varnam,
                                                       ctxdef->method,
                                                       ctxdef->arg);

            for (i = 0;  i < ctxdef->nact;  i++) {
                act = ctxdef->acts + i;

                switch (act->type) {

                case pa_policy_set_property:
                    setprop = &act->setprop;

                    if (rule != NULL) {
                        pa_policy_context_add_property_action(
                                          u,
                                          rule, act->lineno,
                                          setprop->objtype,
                                          setprop->method,
                                          setprop->arg,
                                          setprop->propnam,
                                          setprop->valtype,
                                          setprop->valarg
                        );
                    }
                    break;

                case pa_policy_delete_property:
                    delprop = &act->delprop;

                    if (rule != NULL) {
                        pa_policy_context_delete_property_action(
                                          u,
                                          rule, act->lineno,
                                          delprop->objtype,
                                          delprop->method,
                                          delprop->arg,
                                          delprop->propnam
                        );
                    }
                    break;

                case pa_policy_set_default:
                    setdef = &act->setdef;

                    if (rule != NULL) {
                        pa_policy_context_set_default_action(
                                          rule, act->lineno,
                                          u,
                                          setdef->activity_group,
                                          setdef->default_state);
                    }

                    break;

                case pa_policy_override:
                    setprop = &act->setprop;

                    if (rule != NULL) {
                        pa_policy_context_override_action(
                                          u,
                                          rule, act->lineno,
                                          setprop->objtype,
                                          setprop->method,
                                          setprop->arg,
                                          setprop->propnam,
                                          setprop->valtype,
                                          setprop->valarg
                        );
                    }

                    break;

                default:
                    break;
                }
            }

            break;

        case section_activity:
            status = 1;
            rule = NULL;
            actdef = sec->def.activity;

            if (actdef->active_nact > 0) {
                pa_policy_activity_add(u, actdef->device);
                rule = pa_policy_activity_add_active_rule(u, actdef->device,
                                                          actdef->method, actdef->name);
            }

            for (i = 0;  i < actdef->active_nact;  i++) {
                act = actdef->active_acts + i;

                switch (act->type) {

                case pa_policy_set_property:
                    setprop = &act->setprop;

                    if (rule != NULL) {
                        pa_policy_context_add_property_action(
                                          u,
                                          rule, act->lineno,
                                          setprop->objtype,
                                          setprop->method,
                                          setprop->arg,
                                          setprop->propnam,
                                          setprop->valtype,
                                          setprop->valarg
                        );
                    }

                    break;
                default:
                    break;
                }
            }

            rule = NULL;
            if (actdef->inactive_nact > 0) {
                pa_policy_activity_add(u, actdef->device);
                rule = pa_policy_activity_add_inactive_rule(u, actdef->device,
                                                            actdef->method, actdef->name);
            }

            for (i = 0;  i < actdef->inactive_nact;  i++) {
                act = actdef->inactive_acts + i;

                switch (act->type) {

                case pa_policy_set_property:
                    setprop = &act->setprop;

                    if (rule != NULL) {
                        pa_policy_context_add_property_action(
                                          u,
                                          rule, act->lineno,
                                          setprop->objtype,
                                          setprop->method,
                                          setprop->arg,
                                          setprop->propnam,
                                          setprop->valtype,
                                          setprop->valarg
                        );
                    }

                    break;
                default:
                    break;
                }
            }

            break;

        case section_variable:
            status = 1;
            break;

        default:
            status = 0;
            break;
        }
        
        sec->type = section_unknown;
        sec->def.any = NULL;
    }

    section_free(sec);

    return status;
}


static int groupdef_parse(int lineno, char *line, struct groupdef *grdef)
{
    int       sts = 0;
    char     *end;

    if (grdef == NULL)
        sts = -1;
    else {
        if (!strncmp(line, "name=", 5)) {
            if (!valid_label(lineno, line+5))
                sts = -1;
            else
                grdef->name = pa_xstrdup(line+5);
        }
        else if (!strncmp(line, "sink=", 5)) {
            if (strchr(line, ':'))
                sts = method_parse(lineno, line+5,
                                   &grdef->sink_method,
                                   &grdef->sink_prop,
                                   &grdef->sink_arg);
            else
                grdef->sink = pa_xstrdup(line+5);
        }
        else if (!strncmp(line, "source=", 7)) {
            if (strchr(line, ':'))
                sts = method_parse(lineno, line+7,
                                   &grdef->source_method,
                                   &grdef->source_prop,
                                   &grdef->source_arg);
            else
                grdef->source = pa_xstrdup(line+7);
        }
        else if (!strncmp(line, "properties=", 11)) {
            grdef->properties = pa_proplist_from_string(line + 11);

            if (!grdef->properties)
                pa_log("incorrect syntax in line %d (%s)", lineno, line + 11);
        }
        else if (!strncmp(line, "flags=", 6)) { 
            grdef->flags = pa_xstrdup(line+6);
            grdef->flags_lineno = lineno;
        }
        else {
            if ((end = strchr(line, '=')) == NULL) {
                pa_log("invalid definition '%s' in line %d", line, lineno);
            }
            else {
                *end = '\0';
                pa_log("groupdef invalid key value '%s' in line %d", line, lineno);
            }
            sts = -1;
        }
    }

    return sts;
}

static int devicedef_parse(int lineno, char *line, struct devicedef *devdef)
{
    int   sts;
    char *end;

    if (devdef == NULL)
        sts = -1;
    else {
        sts = 0;

        if (!strncmp(line, "type=", 5)) {
            devdef->type = pa_xstrdup(line+5);
        }
        else if (!strncmp(line, "sink=", 5)) {
            devdef->class = device_sink;
            sts = method_parse(lineno, line+5,
                               &devdef->method,
                               &devdef->prop,
                               &devdef->arg);
        }
        else if (!strncmp(line, "source=", 7)) {
            devdef->class = device_source;
            sts = method_parse(lineno, line+7,
                               &devdef->method,
                               &devdef->prop,
                               &devdef->arg);
        }
        else if (!strncmp(line, "ports=", 6)) {
            sts = ports_parse(lineno, line+6, devdef);
        }
        else if (!strncmp(line, "module=", 7)) {
            sts = module_parse(lineno, line+7, devdef);
        }
        else if (!strncmp(line, "delay=", 6)) {
            devdef->delay = pa_xstrdup(line+6);
            devdef->delay_lineno = lineno;
        }
        else if (!strncmp(line, "flags=", 6)) {
            devdef->flags = pa_xstrdup(line+6);
            devdef->flags_lineno = lineno;
        }
        else {
            if ((end = strchr(line, '=')) == NULL) {
                pa_log("invalid definition '%s' in line %d", line, lineno);
            }
            else {
                *end = '\0';
                pa_log("devicedef invalid key value '%s' in line %d", line, lineno);
            }
            sts = -1;
        }
    }

    return sts;
}

static int carddef_parse(int lineno, char *line, struct carddef *carddef)
{
    int   sts;
    char *end;

    if (carddef == NULL)
        sts = -1;
    else {
        sts = 0;

        if (!strncmp(line, "type=", 5)) {
            carddef->type = pa_xstrdup(line+5);
        }
        else if (!strncmp(line, "name=", 5)) {
            sts = cardname_parse(lineno, line+5, carddef, 0);
        }
        else if (!strncmp(line, "name0=", 6)) {
            sts = cardname_parse(lineno, line+6, carddef, 0);
        }
        else if (!strncmp(line, "name1=", 6)) {
            sts = cardname_parse(lineno, line+6, carddef, 1);
        }
        else if (!strncmp(line, "profile=", 8)) {
            carddef->profile[0] = pa_xstrdup(line+8);
        }
        else if (!strncmp(line, "profile0=", 9)) {
            carddef->profile[0] = pa_xstrdup(line+9);
        }
        else if (!strncmp(line, "profile1=", 9)) {
            if (carddef->profile[0])
                carddef->profile[1] = pa_xstrdup(line+9);
            else {
                pa_log("profile1 cannot be defined without profile0 in line %d", lineno);
                sts = -1;
            }
        }
        else if (!strncmp(line, "flags=", 6)) {
            carddef->flags[0] = pa_xstrdup(line+6);
            carddef->flags_lineno[0] = lineno;
        }
        else if (!strncmp(line, "flags0=", 7)) {
            carddef->flags[0] = pa_xstrdup(line+7);
            carddef->flags_lineno[0] = lineno;
        }
        else if (!strncmp(line, "flags1=", 7)) {
            carddef->flags[1] = pa_xstrdup(line+7);
            carddef->flags_lineno[1] = lineno;
        }
        else {
            if ((end = strchr(line, '=')) == NULL) {
                pa_log("invalid definition '%s' in line %d", line, lineno);
            }
            else {
                *end = '\0';
                pa_log("carddef invalid key value '%s' in line %d", line, lineno);
            }
            sts = -1;
        }
    }

    return sts;
}

static int streamdef_parse(int lineno, char *line, struct streamdef *strdef)
{
    int            sts;
    char          *user;
    struct passwd *pwd;
    int            uid;
    char          *end;

    if (strdef == NULL)
        sts = -1;
    else {
        sts = 0;

        if (!strncmp(line, "name=", 5)) {
            strdef->prop   = pa_xstrdup(PA_PROP_MEDIA_NAME);
            strdef->method = pa_method_equals;
            strdef->arg = pa_xstrdup(line+5);
        }
        else if (!strncmp(line, "property=", 9)) {
            sts = streamprop_parse(lineno, line+9, strdef);
        }
        else if (!strncmp(line, "client=", 7)) {
            strdef->clnam = pa_xstrdup(line+7);
        }
        else if (!strncmp(line, "sink=", 5)) {
            strdef->sname = pa_xstrdup(line+5);
        }
        else if (!strncmp(line, "user=", 5)) {
            user = line+5;
            uid  = strtol(user, &end, 10);

            if (end == user || *end != '\0' || uid < 0) {
                uid = -1;
                setpwent();

                while ((pwd = getpwent()) != NULL) {
                    if (!strcmp(user, pwd->pw_name)) {
                        uid = pwd->pw_uid;
                        break;
                    }
                }

                if (uid < 0) {
                    pa_log("invalid user '%s' in line %d", user, lineno);
                    sts = -1;
                }

                endpwent();
            }

            strdef->uid = (uid_t) uid;
        }
        else if (!strncmp(line, "exe=", 4)) {
            strdef->exe = pa_xstrdup(line+4);
        }
        else if (!strncmp(line, "group=", 6)) {
            strdef->group = pa_xstrdup(line+6);
        }
        else if (!strncmp(line, "flags=", 6)) {
            strdef->flags = pa_xstrdup(line+6);
            strdef->flags_lineno = lineno;
        }
        else if (!strncmp(line, "port_if_active=", 15)) {
            strdef->port = pa_xstrdup(line+15);
        }
        else {
            if ((end = strchr(line, '=')) == NULL) {
                pa_log("invalid definition '%s' in line %d", line, lineno);
            }
            else {
                *end = '\0';
                pa_log("streamdef invalid key value '%s' in line %d", line, lineno);
            }
            sts = -1;
        }
    }

    return sts;
}

static int contextdef_parse(int lineno, char *line, struct contextdef *ctxdef)
{
    int   sts;
    char *end;

    if (ctxdef == NULL)
        sts = -1;
    else {
        sts = 0;

        if (!strncmp(line, "variable=", 9)) {
            ctxdef->varnam = pa_xstrdup(line+9);
        }
        else if (!strncmp(line, "value=", 6)) {
            sts = contextval_parse(lineno, line+6, &ctxdef->method, &ctxdef->arg);
        }
        else if (!strncmp(line, "set-property=", 13)) {
            sts = contextsetprop_parse(lineno, line+13, &ctxdef->nact, &ctxdef->acts);
        }
        else if (!strncmp(line, "delete-property=", 16)) { 
            sts = contextdelprop_parse(lineno, line+16, &ctxdef->nact, &ctxdef->acts);
        }
        else if (!strncmp(line, "set-default=", 12)) {
            sts = contextsetdef_parse(lineno, line+12, &ctxdef->nact, &ctxdef->acts);
        }
        else if (!strncmp(line, "override=", 9)) {
            sts = contextoverride_parse(lineno, line+9, &ctxdef->nact, &ctxdef->acts);
        }
        else {
            if ((end = strchr(line, '=')) == NULL) {
                pa_log("invalid definition '%s' in line %d", line, lineno);
            }
            else {
                *end = '\0';
                pa_log("contextdef invalid key value '%s' in line %d", line, lineno);
            }
            sts = -1;
        }
    }

    return sts;
}

static int activitydef_parse(int lineno, char *line, struct activitydef *actdef)
{
    int sts;
    char *end;

    if (actdef == NULL)
        sts = -1;
    else {
        sts = 0;

        if (!strncmp(line, "sink-name=", 10)) {
            sts = contextval_parse(lineno, line+10, &actdef->method, &actdef->name);
        }
        else if (!strncmp(line, "device=", 7)) {
            actdef->device = pa_xstrdup(line+7);
        }
        else if (!strncmp(line, "active=", 7)) {
            sts = contextsetprop_parse(lineno, line+7, &actdef->active_nact, &actdef->active_acts);
        }
        else if (!strncmp(line, "inactive=", 9)) {
            sts = contextsetprop_parse(lineno, line+9, &actdef->inactive_nact, &actdef->inactive_acts);
        }
        else {
            if ((end = strchr(line, '=')) == NULL) {
                pa_log("invalid definition '%s' in line %d", line, lineno);
            }
            else {
                *end = '\0';
                pa_log("activitydef invalid key value '%s' in line %d", line, lineno);
            }
            sts = -1;
        }
    }

    return sts;
}

static int variabledef_parse(int lineno, char *line, char **ret_var, char **ret_value)
{
    int sts;
    char *var;
    char *value;

    if (ret_var == NULL || ret_value == NULL)
        sts = -1;
    else {
        sts = 0;
        if ((value = strchr(line, '=')) == NULL) {
            pa_log("invalid definition '%s' in line %d", line, lineno);
            sts = -1;
        } else {
            var = line;
            value[0] = '\0';
            value = value + 1;
            *ret_var = pa_sprintf_malloc("$%s", var);
            *ret_value = pa_xstrdup(value);
        }
    }

    return sts;
}

static int method_parse(int lineno, char *definition,
                        enum pa_classify_method *method_val,
                        char **method_prop,
                        char **method_arg)
{
    char *colon;
    char *at;
    const char *prop;
    const char *method;
    const char *arg;

    pa_assert(definition);
    pa_assert(method_val);
    pa_assert(method_prop);
    pa_assert(method_arg);

    if ((colon = strchr(definition, ':')) == NULL) {
        pa_log("invalid definition '%s' in line %d", definition, lineno);
        return -1;
    }

    *colon = '\0';
    arg    = colon + 1;

    if ((at = strchr(definition, '@')) == NULL) {
        prop   = "(name)";
        method = definition;
    }
    else {
        *at    = '\0';
        prop   = definition;
        method = at + 1;
    }

    if (!strcmp(method, "equals"))
        *method_val = pa_method_equals;
    else if (!strcmp(method, "startswith"))
        *method_val = pa_method_startswith;
    else if (!strcmp(method, "matches"))
        *method_val = pa_method_matches;
    else {
        pa_log("invalid method '%s' in line %d", method, lineno);
        return -1;
    }

    *method_prop = pa_xstrdup(prop);
    *method_arg  = pa_xstrdup(arg);

    return 0;
}

static int ports_parse(int lineno, const char *portsdef,
                       struct devicedef *devdef)
{
    char **entries;

    if (devdef->ports) {
        pa_log("Duplicate ports= line in line %d, using the last "
               "occurrence.", lineno);

        pa_hashmap_free(devdef->ports);
    }

    devdef->ports = pa_hashmap_new_full(pa_idxset_string_hash_func,
                                        pa_idxset_string_compare_func,
                                        NULL,
                                        (pa_free_cb_t) pa_classify_port_entry_free);

    if ((entries = split_strv(portsdef, ","))) {
        char *entry; /* This string has format "sinkname:portname". */
        int i = 0;

        while ((entry = entries[i++])) {
            struct pa_classify_port_entry *port;
            size_t entry_len;
            size_t colon_pos;

            if (!*entry) {
                pa_log_debug("Ignoring a redundant comma in line %d", lineno);
                continue;
            }

            entry_len = strlen(entry);
            colon_pos = strcspn(entry, ":");

            if (colon_pos == entry_len) {
                pa_log("Colon missing in port entry '%s' in line %d, ignoring "
                       "the entry", entry, lineno);
                continue;
            } else if (colon_pos == 0) {
                pa_log("Empty device name in port entry '%s' in line %d, "
                       "ignoring the entry", entry, lineno);
                continue;
            } else if (colon_pos == entry_len - 1) {
                pa_log("Empty port name in port entry '%s' in line %d, "
                       "ignoring the entry", entry, lineno);
                continue;
            }

            port = pa_xnew(struct pa_classify_port_entry, 1);
            port->device_name = pa_xstrndup(entry, colon_pos);
            port->port_name = pa_xstrdup(entry + colon_pos + 1);

            if (pa_hashmap_put(devdef->ports, port->device_name, port) < 0) {
                pa_log("Duplicate device name in port entry '%s' in line %d, "
                       "using the first occurrence", entry, lineno);

                pa_classify_port_entry_free(port);
            }
        }

        pa_xstrfreev(entries);

    } else
        pa_log_warn("Empty ports= definition in line %d", lineno);

    return 0;
}

static int module_parse(int lineno, const char *portsdef,
                       struct devicedef *devdef)
{
    char **entries;

    if (devdef->module) {
        pa_log("Duplicate module= line in line %d, using the last "
               "occurrence.", lineno);

        pa_xfree(devdef->module);
        pa_xfree(devdef->module_args);
        devdef->module = NULL;
        devdef->module_args = NULL;
    }

    if ((entries = split_strv(portsdef, "@"))) {
        if (!entries[0]) {
            pa_log("Empty module part in module= definition in line %d", lineno);
            pa_xstrfreev(entries);
            return -1;
        }

        devdef->module = pa_xstrdup(entries[0]);
        devdef->module_args = entries[1] ? pa_replace(entries[1], "%20", " ") : NULL;

        pa_xstrfreev(entries);

    } else
        pa_log_warn("Empty module= definition in line %d", lineno);

    return 0;
}

static void delay_parse(struct userdata *u, int lineno,
                        const char *delaydef, uint32_t *delay)
{
    char *end;

    pa_assert(delay);

    if (delaydef && *delaydef != '\0') {
        pa_policy_var_update(u, delaydef);
        *delay = strtoul(delaydef, &end, 10);
        if (*end != '\0')
            *delay = 0;
    }
}

static int streamprop_parse(int lineno,char *propdef,struct streamdef *strdef)
{
    char *colon;
    char *at;
    char *prop;
    char *method;
    char *arg;

    if ((colon = strchr(propdef, ':')) == NULL) {
        pa_log("invalid definition '%s' in line %d", propdef, lineno);
        return -1;
    }

    *colon = '\0';
    arg    = colon + 1;

    if ((at = strchr(propdef, '@')) == NULL) {
        pa_log("invalid definition '%s' in line %d", propdef, lineno);
        return -1;
    }

    *at    = '\0';
    prop   = propdef;
    method = at + 1;
    
    if (!strcmp(method, "equals"))
        strdef->method = pa_method_equals;
    else if (!strcmp(method, "startswith"))
        strdef->method = pa_method_startswith;
    else if (!strcmp(method, "matches"))
        strdef->method = pa_method_matches;
    else {
        pa_log("invalid method '%s' in line %d", method, lineno);
        return -1;
    }
    
    strdef->prop  = pa_xstrdup(prop);
    strdef->arg   = pa_xstrdup(arg);
    
    return 0;
}

static int contextval_parse(int lineno,char *valdef, enum pa_classify_method *method_val, char **method_arg)
{
    char *colon;
    char *method;
    char *arg;

    if ((colon = strchr(valdef, ':')) == NULL) {
        pa_log("invalid definition '%s' in line %d", valdef, lineno);
        return -1;
    }

    *colon = '\0';
    method = valdef;
    arg    = colon + 1;
    
    if (!strcmp(method, "equals"))
        *method_val = pa_method_equals;
    else if (!strcmp(method, "startswith"))
        *method_val = pa_method_startswith;
    else if (!strcmp(method, "matches"))
        *method_val = strcmp(arg, "*") ? pa_method_matches : pa_method_true;
    else {
        pa_log("invalid method '%s' in line %d", method, lineno);
        return -1;
    }
    
    *method_arg = (*method_val == pa_method_true) ? NULL : pa_xstrdup(arg);
    
    return 0;
}

static int contextsetprop_parse(int lineno, char *setpropdef,
                                int *nact, struct ctxact **acts)
{
    size_t          size;
    struct ctxact  *act;
    struct setprop *setprop;
    struct anyprop *anyprop;
    char           *comma1;
    char           *comma2;
    char           *objdef;
    char           *propdef;
    char           *valdef;
    char           *valarg;

    /*
     * sink-name@startswidth:alsa,property:foo,value@constant:bar
     */

    size = sizeof(*act) * (*nact + 1);
    act  = (*acts = pa_xrealloc(*acts, size)) + *nact;

    memset(act, 0, sizeof(*act));
    act->type   = pa_policy_set_property;
    act->lineno = lineno;

    setprop = &act->setprop;
    anyprop = &act->anyprop;

    if ((comma1 = strchr(setpropdef, ',')) == NULL ||
        (comma2 = strchr(comma1 + 1, ',')) == NULL   )
    {
        pa_log("invalid definition '%s' in line %d", setpropdef, lineno);
        return -1;
    }

    *comma1 = '\0';
    *comma2 = '\0';
    
    objdef  = setpropdef;
    propdef = comma1 + 1;
    valdef  = comma2 + 1;

    if (strncmp(propdef, "property:", 9) != 0) {
        pa_log("invalid argument '%s' in line %d", propdef, lineno);
        return -1;
    }

    if (!strncmp(valdef, "value@constant:", 15)) {
        setprop->valtype = pa_policy_value_constant;
        valarg = valdef + 15;
    }
    else if (!strncmp(valdef, "value@copy-from-context", 23)) {
        setprop->valtype = pa_policy_value_copy;
        valarg = NULL;
    }
    else {
        pa_log("invalid value definition '%s' in line %d", valdef, lineno);
        return -1;
    }
    
    if (contextanyprop_parse(lineno, objdef, propdef, anyprop) < 0)
        return -1;

    setprop->valarg  = valarg ? pa_xstrdup(valarg) : NULL;

    (*nact)++;
    
    return 0;
}

static int contextdelprop_parse(int lineno, char *delpropdef,
                                int *nact, struct ctxact **acts)
{
    size_t          size;
    struct ctxact  *act;
    struct anyprop *anyprop;
    char           *comma;
    char           *objdef;
    char           *propdef;

    /*
     * sink-name@startswidth:alsa,property:foo
     */

    size = sizeof(*act) * (*nact + 1);
    act  = (*acts = pa_xrealloc(*acts, size)) + *nact;

    memset(act, 0, sizeof(*act));
    act->type   = pa_policy_delete_property;
    act->lineno = lineno;

    anyprop = &act->anyprop;

    if ((comma = strchr(delpropdef, ',')) == NULL) {
        pa_log("invalid definition '%s' in line %d", delpropdef, lineno);
        return -1;
    }

    *comma = '\0';
    
    objdef  = delpropdef;
    propdef = comma + 1;

    if (contextanyprop_parse(lineno, objdef, propdef, anyprop) < 0)
        return -1;

    (*nact)++;
    
    return 0;
}

static int contextsetdef_parse(int lineno, char *setdefdef,
                                int *nact, struct ctxact **acts)
{
    size_t          size;
    struct ctxact  *act;
    struct setdef  *setdef;
    char           *colon;
    char           *activity_group;
    char           *value;
    int             default_state;

    /*
     * activity-group:<active/inactive/state>
     */

    size = sizeof(*act) * (*nact + 1);
    act  = (*acts = pa_xrealloc(*acts, size)) + *nact;

    memset(act, 0, sizeof(*act));
    act->type   = pa_policy_set_default;
    act->lineno = lineno;

    setdef = &act->setdef;

    if ((colon = strchr(setdefdef, ':')) == NULL) {
        pa_log("invalid definition '%s' in line %d", setdefdef, lineno);
        return -1;
    }

    *colon = '\0';

    activity_group = setdefdef;
    value = colon + 1;

    if (!strncmp(value, "active", 6))
        default_state = 1;
    else if (!strncmp(value, "inactive", 8))
        default_state = 0;
    else if (!strncmp(value, "state", 5))
        default_state = -1;
    else {
        pa_log("invalid value definition '%s' in line %d", value, lineno);
        return -1;
    }

    setdef->activity_group = pa_xstrdup(activity_group);
    setdef->default_state = default_state;

    (*nact)++;

    return 0;
}

static int contextoverride_parse(int lineno, char *setoverridedef,
                                int *nact, struct ctxact **acts)
{
    size_t          size;
    struct ctxact  *act;
    struct setprop *setprop;
    struct anyprop *anyprop;
    char           *comma1;
    char           *comma2;
    char           *objdef;
    char           *propdef;
    char           *valdef;
    char           *valarg;

    /*
     * card-name@startswidth:foo,profile:bar,value@constant:foobar
     */

    size = sizeof(*act) * (*nact + 1);
    act  = (*acts = pa_xrealloc(*acts, size)) + *nact;

    memset(act, 0, sizeof(*act));
    act->type   = pa_policy_override;
    act->lineno = lineno;

    setprop = &act->setprop;
    anyprop = &act->anyprop;

    if ((comma1 = strchr(setoverridedef, ',')) == NULL ||
        (comma2 = strchr(comma1 + 1, ',')) == NULL   )
    {
        pa_log("invalid definition '%s' in line %d", setoverridedef, lineno);
        return -1;
    }

    *comma1 = '\0';
    *comma2 = '\0';

    objdef  = setoverridedef;
    propdef = comma1 + 1;
    valdef  = comma2 + 1;

    if (strncmp(propdef, "profile:", 8) != 0) {
        pa_log("invalid argument '%s' in line %d", propdef, lineno);
        return -1;
    }

    if (!strncmp(valdef, "value@constant:", 15)) {
        setprop->valtype = pa_policy_value_constant;
        valarg = valdef + 15;
    }
    else {
        pa_log("invalid value definition '%s' in line %d", valdef, lineno);
        return -1;
    }

    if (contextanyprop_parse(lineno, objdef, propdef, anyprop) < 0)
        return -1;

    setprop->valarg  = valarg ? pa_xstrdup(valarg) : NULL;

    (*nact)++;

    return 0;

}

static int contextanyprop_parse(int lineno, char *objdef, char *propdef,
                                struct anyprop *anyprop)
{
    char          *colon;
    char          *method;
    char          *arg;
    char          *propnam;

    /*
     * objdef  = "sink-name@startswidth:alsa"
     * propdef = "property:foo"
     */
    if (!strncmp(objdef, "module-name@", 12)) {
        anyprop->objtype = pa_policy_object_module;
        method = objdef + 12;
    }
    else if (!strncmp(objdef, "card-name@", 10)) {
        anyprop->objtype = pa_policy_object_card;
        method = objdef + 10;
    } 
    else if (!strncmp(objdef, "sink-name@", 10)) {
        anyprop->objtype = pa_policy_object_sink;
        method = objdef + 10;
    }
    else if (!strncmp(objdef, "source-name@", 12)) {
        anyprop->objtype = pa_policy_object_source;
        method = objdef + 12;
    }
    else if (!strncmp(objdef, "sink-input-name@", 16)) {
        anyprop->objtype = pa_policy_object_sink_input;
        method = objdef + 16;
    }
    else if (!strncmp(objdef, "source-output-name@", 19)) {
        anyprop->objtype = pa_policy_object_source_output;
        method = objdef + 19;
    }
    else {
        pa_log("invalid object definition in line %d", lineno);
        return -1;
    }

    if ((colon = strchr(method, ':')) == NULL) {
        pa_log("invalid object definition in line %d", lineno);
        return -1;
    }

    *colon = '\0';
    arg = colon + 1;


    if (!strcmp(method, "equals"))
        anyprop->method = pa_method_equals;
    else if (!strcmp(method, "startswith"))
        anyprop->method = pa_method_startswith;
    else if (!strcmp(method, "matches"))
        anyprop->method = pa_method_matches;
    else {
        pa_log("invalid method '%s' in line %d", method, lineno);
        return -1;
    }
    
    if (!strncmp(propdef, "property:", 9))
        propnam = propdef + 9;
    else if (!strncmp(propdef, "profile:", 8))
        propnam = propdef + 8;
    else {
        pa_log("invalid property definition '%s' in line %d", propdef, lineno);
        return -1;
    }

    anyprop->arg     = pa_xstrdup(arg);
    anyprop->propnam = pa_xstrdup(propnam);
    
    return 0;
}

static int cardname_parse(int lineno, char *namedef, struct carddef *carddef, int field)
{
    char *colon;
    char *method;
    char *arg;

    if ((colon = strchr(namedef, ':')) == NULL) {
        pa_log("invalid definition '%s' in line %d", namedef, lineno);
        return -1;
    }

    *colon = '\0';
    method = namedef;
    arg    = colon + 1;

    if (!strcmp(method, "equals"))
        carddef->method[field] = pa_method_equals;
    else if (!strcmp(method, "startswith"))
        carddef->method[field] = pa_method_startswith;
    else if (!strcmp(method, "matches"))
        carddef->method[field] = pa_method_matches;
    else {
        pa_log("invalid method '%s' in line %d", method, lineno);
        return -1;
    }
    
    carddef->arg[field]   = pa_xstrdup(arg);
    
    return 0;
}

static int flags_parse(struct userdata  *u,
                       int               lineno,
                       const char       *flagdef,
                       enum section_type sectn,
                       uint32_t         *flags_ret)
{
    char       *comma;
    const char *flagname;
    uint32_t    flags;
    int         device, card, stream, group;

    flags = 0;

    if (!flagdef)
        goto done;

    pa_policy_var_update(u, flagdef);

    device = card = stream = group = false;

    switch (sectn) {
    case section_device:   device = true;   break;
    case section_card:     card   = true;   break;
    case section_stream:   stream = true;   break;
    case section_group:    group  = true;   break;
    default:                                break;
    }


    while (*(flagname = flagdef) != '\0') {
        if ((comma = strchr(flagdef, ',')) == NULL)
            flagdef += strlen(flagdef);
        else {
            *comma = '\0';
            flagdef = comma + 1;
        }

        flagname = pa_policy_var(u, flagname);

        if ((device || card) && !strcmp(flagname, "disable_notify"))
            flags |= PA_POLICY_DISABLE_NOTIFY;

        else if (device && !strcmp(flagname, "refresh_always"))
            flags |= PA_POLICY_REFRESH_PORT_ALWAYS;
        else if (device && !strcmp(flagname, "delayed_port_change"))
            flags |= PA_POLICY_DELAYED_PORT_CHANGE;
        else if (device && !strcmp(flagname, "module_unload_immediately"))
            flags |= PA_POLICY_MODULE_UNLOAD_IMMEDIATELY;

        else if (stream && !strcmp(flagname, "mute_if_active"))
            flags |= PA_POLICY_LOCAL_MUTE;
        else if (stream && !strcmp(flagname, "max_volume"))
            flags |= PA_POLICY_LOCAL_VOLMAX;

        else if (card && !strcmp(flagname, "notify_profile_changed"))
            flags |= PA_POLICY_NOTIFY_PROFILE_CHANGED;

        else if (group && !strcmp(flagname, "client"))
            flags = PA_POLICY_GROUP_FLAGS_CLIENT;
        else if (group && !strcmp(flagname, "nopolicy"))
            flags = PA_POLICY_GROUP_FLAGS_NOPOLICY;
        else if (group && !strcmp(flagname, "set_sink"))
            flags |= PA_POLICY_GROUP_FLAG_SET_SINK;
        else if (group && !strcmp(flagname, "set_source"))
            flags |= PA_POLICY_GROUP_FLAG_SET_SOURCE;
        else if (group && !strcmp(flagname, "route_audio"))
            flags |= PA_POLICY_GROUP_FLAG_ROUTE_AUDIO;
        else if (group && !strcmp(flagname, "limit_volume"))
            flags |= PA_POLICY_GROUP_FLAG_LIMIT_VOLUME;
        else if (group && !strcmp(flagname, "cork_stream"))
            flags |= PA_POLICY_GROUP_FLAG_CORK_STREAM;
        else if (group && !strcmp(flagname, "mute_by_route"))
            flags |= PA_POLICY_GROUP_FLAG_MUTE_BY_ROUTE;
        else if (group && !strcmp(flagname, "media_notify"))
            flags |= PA_POLICY_GROUP_FLAG_MEDIA_NOTIFY;
        else if (group && !strcmp(flagname, "dynamic_sink"))
            flags |= PA_POLICY_GROUP_FLAG_DYNAMIC_SINK;
        else if (strlen(flagname) > 0)
            pa_log("invalid flag '%s' in line %d", flagname, lineno);
    }

done:
    *flags_ret = flags;

    return 0;
}

static int valid_label(int lineno, char *label)
{
    int c;

    if (!isalpha(*label))
        goto invalid;

    while((c = *label++) != '\0') {
        if (!isalpha(c) && isdigit(c) && c != '-' && c != '_')
            goto invalid;
    }

    return 1;

 invalid:
    pa_log("invalid label '%s' in line %d", label, lineno);
    return 0;
}

/* Same functionality as in PulseAudio pulsecore/core-util.c
 * pa_split_spaces_strv() with added user definable delimiter. */
static char **split_strv(const char *s, const char *delimiter) {
    char **t, *e;
    unsigned i = 0, n = 8;
    const char *state = NULL;

    t = pa_xnew(char*, n);
    while ((e = pa_split(s, delimiter, &state))) {
        t[i++] = e;

        if (i >= n) {
            n *= 2;
            t = pa_xrenew(char*, t, n);
        }
    }

    if (i <= 0) {
        pa_xfree(t);
        return NULL;
    }

    t[i] = NULL;
    return t;
}

const char *policy_file_path(const char *file, char *buf, size_t len)
{
    snprintf(buf, len, "%s/%s", PA_DEFAULT_CONFIG_DIR, file);

    return buf;
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
