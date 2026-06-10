// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// Frida-less device backend. meson compiles this in place of
// rz_frida_backend.c when frida-core is unavailable, so the backend entry
// points stay linkable and report that Frida support is not enabled.

#include <rz_frida.h>

RZ_IPI void rz_frida_backend_init(void) {
}

RZ_IPI void rz_frida_backend_deinit(void) {
}

RZ_IPI bool rz_frida_devices_json(PJ *pj) {
	rz_return_val_if_fail(pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_processes_json(RZ_UNUSED const RzFridaUri *uri, PJ *pj) {
	rz_return_val_if_fail(pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_apps_json(RZ_UNUSED const RzFridaUri *uri, PJ *pj) {
	rz_return_val_if_fail(pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_open(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_resume(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_close(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_eval(RzFridaSession *session, RZ_UNUSED const char *source, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}

RZ_IPI bool rz_frida_backend_ping(RzFridaSession *session, PJ *pj) {
	rz_return_val_if_fail(session && pj, false);
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE, "frida-core support is not enabled");
	return false;
}
