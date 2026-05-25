// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

#include <stdlib.h>
#include <string.h>

static char *rz_frida_str_ndup(const char *start, size_t len) {
	char *out = (char *)calloc(len + 1, 1);
	if (!out) {
		return NULL;
	}
	memcpy(out, start, len);
	return out;
}

static char *rz_frida_str_dup(const char *str) {
	return str ? rz_frida_str_ndup(str, strlen(str)) : NULL;
}

static bool assign_part(char **dst, const char **cursor, bool rest) {
	const char *start = *cursor;
	const char *slash = strchr(start, '/');
	size_t len = (!rest && slash) ? (size_t)(slash - start) : strlen(start);
	*dst = rz_frida_str_ndup(start, len);
	if (!*dst) {
		return false;
	}
	*cursor = (!rest && slash) ? slash + 1 : start + len;
	return true;
}

static bool uri_has_more_fields(const char *cursor) {
	return cursor && strchr(cursor, '/');
}

static bool target_action(RzFridaAction action) {
	return action == RZ_FRIDA_ACTION_ATTACH ||
		action == RZ_FRIDA_ACTION_SPAWN ||
		action == RZ_FRIDA_ACTION_LAUNCH;
}

const char *rz_frida_action_string(RzFridaAction action) {
	switch (action) {
	case RZ_FRIDA_ACTION_LIST:
		return "list";
	case RZ_FRIDA_ACTION_APPS:
		return "apps";
	case RZ_FRIDA_ACTION_ATTACH:
		return "attach";
	case RZ_FRIDA_ACTION_SPAWN:
		return "spawn";
	case RZ_FRIDA_ACTION_LAUNCH:
		return "launch";
	case RZ_FRIDA_ACTION_UNKNOWN:
	default:
		return "unknown";
	}
}

RzFridaAction rz_frida_action_from_string(const char *action) {
	if (!action) {
		return RZ_FRIDA_ACTION_UNKNOWN;
	}
	if (!strcmp(action, "list")) {
		return RZ_FRIDA_ACTION_LIST;
	}
	if (!strcmp(action, "apps")) {
		return RZ_FRIDA_ACTION_APPS;
	}
	if (!strcmp(action, "attach")) {
		return RZ_FRIDA_ACTION_ATTACH;
	}
	if (!strcmp(action, "spawn")) {
		return RZ_FRIDA_ACTION_SPAWN;
	}
	if (!strcmp(action, "launch")) {
		return RZ_FRIDA_ACTION_LAUNCH;
	}
	return RZ_FRIDA_ACTION_UNKNOWN;
}

const char *rz_frida_transport_string(RzFridaTransport transport) {
	switch (transport) {
	case RZ_FRIDA_TRANSPORT_LOCAL:
		return "local";
	case RZ_FRIDA_TRANSPORT_USB:
		return "usb";
	case RZ_FRIDA_TRANSPORT_REMOTE:
		return "remote";
	case RZ_FRIDA_TRANSPORT_UNKNOWN:
	default:
		return "unknown";
	}
}

RzFridaTransport rz_frida_transport_from_string(const char *transport) {
	if (!transport) {
		return RZ_FRIDA_TRANSPORT_UNKNOWN;
	}
	if (!strcmp(transport, "local")) {
		return RZ_FRIDA_TRANSPORT_LOCAL;
	}
	if (!strcmp(transport, "usb")) {
		return RZ_FRIDA_TRANSPORT_USB;
	}
	if (!strcmp(transport, "remote")) {
		return RZ_FRIDA_TRANSPORT_REMOTE;
	}
	return RZ_FRIDA_TRANSPORT_UNKNOWN;
}

void rz_frida_uri_fini(RzFridaUri *uri) {
	if (!uri) {
		return;
	}
	free(uri->action);
	free(uri->transport);
	free(uri->device);
	free(uri->target);
	memset(uri, 0, sizeof(*uri));
}

bool rz_frida_uri_copy(RzFridaUri *dst, const RzFridaUri *src) {
	if (!dst || !src) {
		return false;
	}
	memset(dst, 0, sizeof(*dst));
	dst->action_type = src->action_type;
	dst->transport_type = src->transport_type;
	dst->action = rz_frida_str_dup(src->action);
	dst->transport = rz_frida_str_dup(src->transport);
	dst->device = rz_frida_str_dup(src->device);
	dst->target = rz_frida_str_dup(src->target);
	if (!dst->action || !dst->transport || !dst->device || !dst->target) {
		rz_frida_uri_fini(dst);
		return false;
	}
	return true;
}

bool rz_frida_uri_parse(const char *uri, RzFridaUri *out) {
	if (!uri || !out) {
		return false;
	}

	memset(out, 0, sizeof(*out));

	const char prefix[] = "frida://";
	const size_t prefix_len = sizeof(prefix) - 1;
	if (strncmp(uri, prefix, prefix_len)) {
		return false;
	}

	const char *cursor = uri + prefix_len;
	if (!assign_part(&out->action, &cursor, false) ||
		!assign_part(&out->transport, &cursor, false) ||
		!assign_part(&out->device, &cursor, false) ||
		!assign_part(&out->target, &cursor, true)) {
		rz_frida_uri_fini(out);
		return false;
	}

	if (uri_has_more_fields(cursor) ||
		!*out->action || !*out->transport ||
		!out->device || !out->target) {
		rz_frida_uri_fini(out);
		return false;
	}

	out->action_type = rz_frida_action_from_string(out->action);
	out->transport_type = rz_frida_transport_from_string(out->transport);
	if (out->action_type == RZ_FRIDA_ACTION_UNKNOWN ||
		out->transport_type == RZ_FRIDA_TRANSPORT_UNKNOWN) {
		rz_frida_uri_fini(out);
		return false;
	}

	if (target_action(out->action_type) && !*out->target) {
		rz_frida_uri_fini(out);
		return false;
	}

	if (out->transport_type == RZ_FRIDA_TRANSPORT_LOCAL && *out->device) {
		rz_frida_uri_fini(out);
		return false;
	}

	if (out->transport_type == RZ_FRIDA_TRANSPORT_USB &&
		out->action_type != RZ_FRIDA_ACTION_LIST && !*out->device) {
		rz_frida_uri_fini(out);
		return false;
	}

	if (out->transport_type == RZ_FRIDA_TRANSPORT_REMOTE) {
		if (!*out->device || !strchr(out->device, ':')) {
			rz_frida_uri_fini(out);
			return false;
		}
	}

	return true;
}
