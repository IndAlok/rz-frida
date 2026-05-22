// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_FRIDA_H
#define RZ_FRIDA_H

#include <rz_types.h>

typedef struct rz_frida_uri_t {
	char *action;
	char *transport;
	char *device;
	char *target;
} RzFridaUri;

bool rz_frida_uri_parse(const char *uri, RzFridaUri *out);
void rz_frida_uri_fini(RzFridaUri *uri);

#endif

