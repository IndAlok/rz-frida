// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

#include <assert.h>
#include <string.h>

int main(void) {
	assert(rz_frida_method_from_string("status") == RZ_FRIDA_METHOD_STATUS);
	assert(rz_frida_method_from_string("devices") == RZ_FRIDA_METHOD_DEVICES);
	assert(rz_frida_method_from_string("bad") == RZ_FRIDA_METHOD_UNKNOWN);
	assert(!strcmp(rz_frida_method_string(RZ_FRIDA_METHOD_LAUNCH), "launch"));
	assert(!strcmp(rz_frida_error_string(RZ_FRIDA_ERROR_INVALID_URI), "invalid_uri"));
	assert(!strcmp(rz_frida_error_string(RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE), "frida_unavailable"));

	RzFridaMethod method = RZ_FRIDA_METHOD_UNKNOWN;
	assert(rz_frida_method_parse("attach", &method, NULL));
	assert(method == RZ_FRIDA_METHOD_ATTACH);

	PJ *pj = pj_new();
	assert(pj);
	rz_frida_json_ok_empty(pj);
	assert(!strcmp(pj_string(pj), "{\"ok\":true,\"result\":{}}"));
	pj_free(pj);

	pj = pj_new();
	assert(pj);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "bad target");
	assert(!strcmp(pj_string(pj), "{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"bad target\"}}"));
	pj_free(pj);

	method = RZ_FRIDA_METHOD_STATUS;
	pj = pj_new();
	assert(pj);
	assert(!rz_frida_method_parse("bad", &method, pj));
	assert(method == RZ_FRIDA_METHOD_UNKNOWN);
	assert(!strcmp(pj_string(pj), "{\"ok\":false,\"error\":{\"code\":\"not_implemented\",\"message\":\"unknown method\"}}"));
	pj_free(pj);

	return 0;
}
