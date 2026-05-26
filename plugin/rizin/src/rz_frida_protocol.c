// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

#include <string.h>

const char *rz_frida_method_string(RzFridaMethod method) {
	switch (method) {
	case RZ_FRIDA_METHOD_STATUS:
		return "status";
	case RZ_FRIDA_METHOD_DEVICES:
		return "devices";
	case RZ_FRIDA_METHOD_PROCESSES:
		return "processes";
	case RZ_FRIDA_METHOD_APPS:
		return "apps";
	case RZ_FRIDA_METHOD_ATTACH:
		return "attach";
	case RZ_FRIDA_METHOD_SPAWN:
		return "spawn";
	case RZ_FRIDA_METHOD_LAUNCH:
		return "launch";
	case RZ_FRIDA_METHOD_DETACH:
		return "detach";
	case RZ_FRIDA_METHOD_UNKNOWN:
	default:
		return "unknown";
	}
}

RzFridaMethod rz_frida_method_from_string(const char *method) {
	if (!method) {
		return RZ_FRIDA_METHOD_UNKNOWN;
	}
	if (!strcmp(method, "status")) {
		return RZ_FRIDA_METHOD_STATUS;
	}
	if (!strcmp(method, "devices")) {
		return RZ_FRIDA_METHOD_DEVICES;
	}
	if (!strcmp(method, "processes")) {
		return RZ_FRIDA_METHOD_PROCESSES;
	}
	if (!strcmp(method, "apps")) {
		return RZ_FRIDA_METHOD_APPS;
	}
	if (!strcmp(method, "attach")) {
		return RZ_FRIDA_METHOD_ATTACH;
	}
	if (!strcmp(method, "spawn")) {
		return RZ_FRIDA_METHOD_SPAWN;
	}
	if (!strcmp(method, "launch")) {
		return RZ_FRIDA_METHOD_LAUNCH;
	}
	if (!strcmp(method, "detach")) {
		return RZ_FRIDA_METHOD_DETACH;
	}
	return RZ_FRIDA_METHOD_UNKNOWN;
}

bool rz_frida_method_parse(const char *method, RzFridaMethod *out, PJ *pj) {
	if (!out) {
		if (pj) {
			rz_frida_json_error(pj, RZ_FRIDA_ERROR_INTERNAL, "missing method output");
		}
		return false;
	}
	*out = rz_frida_method_from_string(method);
	if (*out != RZ_FRIDA_METHOD_UNKNOWN) {
		return true;
	}
	if (pj) {
		rz_frida_json_error(pj, RZ_FRIDA_ERROR_NOT_IMPLEMENTED, method ? "unknown method" : "missing method");
	}
	return false;
}

const char *rz_frida_error_string(RzFridaError error) {
	switch (error) {
	case RZ_FRIDA_ERROR_NONE:
		return "none";
	case RZ_FRIDA_ERROR_INVALID_URI:
		return "invalid_uri";
	case RZ_FRIDA_ERROR_INVALID_TARGET:
		return "invalid_target";
	case RZ_FRIDA_ERROR_TIMEOUT:
		return "timeout";
	case RZ_FRIDA_ERROR_CANCELLED:
		return "cancelled";
	case RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE:
		return "frida_unavailable";
	case RZ_FRIDA_ERROR_NOT_IMPLEMENTED:
		return "not_implemented";
	case RZ_FRIDA_ERROR_INTERNAL:
	default:
		return "internal_error";
	}
}

void rz_frida_json_ok_begin(PJ *pj) {
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_kb(pj, "ok", true);
	pj_ko(pj, "result");
}

void rz_frida_json_ok_end(PJ *pj) {
	if (!pj) {
		return;
	}
	pj_end(pj);
	pj_end(pj);
}

void rz_frida_json_ok_empty(PJ *pj) {
	rz_frida_json_ok_begin(pj);
	rz_frida_json_ok_end(pj);
}

void rz_frida_json_error(PJ *pj, RzFridaError error, const char *message) {
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_kb(pj, "ok", false);
	pj_ko(pj, "error");
	pj_ks(pj, "code", rz_frida_error_string(error));
	pj_ks(pj, "message", message ? message : rz_frida_error_string(error));
	pj_end(pj);
	pj_end(pj);
}
