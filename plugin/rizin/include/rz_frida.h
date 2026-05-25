// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_FRIDA_H
#define RZ_FRIDA_H

#include <rz_types.h>

typedef enum rz_frida_action_t {
	RZ_FRIDA_ACTION_UNKNOWN = 0,
	RZ_FRIDA_ACTION_LIST,
	RZ_FRIDA_ACTION_APPS,
	RZ_FRIDA_ACTION_ATTACH,
	RZ_FRIDA_ACTION_SPAWN,
	RZ_FRIDA_ACTION_LAUNCH,
} RzFridaAction;

typedef enum rz_frida_transport_t {
	RZ_FRIDA_TRANSPORT_UNKNOWN = 0,
	RZ_FRIDA_TRANSPORT_LOCAL,
	RZ_FRIDA_TRANSPORT_USB,
	RZ_FRIDA_TRANSPORT_REMOTE,
} RzFridaTransport;

typedef struct rz_frida_uri_t {
	RzFridaAction action_type;
	RzFridaTransport transport_type;
	char *action;
	char *transport;
	char *device;
	char *target;
} RzFridaUri;

const char *rz_frida_action_string(RzFridaAction action);
RzFridaAction rz_frida_action_from_string(const char *action);
const char *rz_frida_transport_string(RzFridaTransport transport);
RzFridaTransport rz_frida_transport_from_string(const char *transport);

bool rz_frida_uri_parse(const char *uri, RzFridaUri *out);
bool rz_frida_uri_copy(RzFridaUri *dst, const RzFridaUri *src);
void rz_frida_uri_fini(RzFridaUri *uri);

#endif
