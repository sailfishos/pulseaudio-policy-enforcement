modlibexec_LTLIBRARIES = module-policy-enforcement.la

module_policy_enforcement_la_SOURCES = \
			module-policy-enforcement.c \
			log.c \
			match.c \
			variable.c \
			index-hash.c \
			config-file.c \
			client-ext.c \
			sink-ext.c \
			source-ext.c \
			sink-input-ext.c \
			source-output-ext.c \
			card-ext.c \
			module-ext.c \
			classify.c \
			policy-group.c \
			context.c \
			dbusif.c \
			policy.c
module_policy_enforcement_la_LDFLAGS = -module -avoid-version
module_policy_enforcement_la_LIBADD = $(AM_LIBADD) $(DBUS_LIBS) $(LIBPULSECORE_LIBS) $(LIBPULSE_LIBS) $(MEEGOCOMMON_LIBS)
module_policy_enforcement_la_CFLAGS = $(AM_CFLAGS) $(DBUS_CFLAGS) $(LIBPULSE_CFLAGS) $(LIBPULSECORE_CFLAGS) $(MEEGOCOMMON_CFLAGS) -DPULSEAUDIO_VERSION=@PA_MAJOR@ -DPA_MODULE_NAME=module_policy_enforcement
