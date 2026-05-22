// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

#include <stdlib.h>

typedef struct rz_frida_session_t {
	ut64 id;
	bool attached;
} RzFridaSession;

RzFridaSession *rz_frida_session_new(void) {
	return (RzFridaSession *)calloc(1, sizeof(RzFridaSession));
}

void rz_frida_session_free(RzFridaSession *session) {
	free(session);
}
