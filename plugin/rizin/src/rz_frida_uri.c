// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

#include <stdlib.h>
#include <string.h>

static char *dup_part(const char *start, size_t len) {
	char *out = (char *)calloc(len + 1, 1);
	if (!out) {
		return NULL;
	}
	memcpy(out, start, len);
	return out;
}

static bool assign_part(char **dst, const char **cursor) {
	const char *start = *cursor;
	const char *slash = strchr(start, '/');
	size_t len = slash ? (size_t)(slash - start) : strlen(start);
	*dst = dup_part(start, len);
	if (!*dst) {
		return false;
	}
	*cursor = slash ? slash + 1 : start + len;
	return true;
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
	if (!assign_part(&out->action, &cursor) ||
		!assign_part(&out->transport, &cursor) ||
		!assign_part(&out->device, &cursor) ||
		!assign_part(&out->target, &cursor)) {
		rz_frida_uri_fini(out);
		return false;
	}

	if (!*out->action || !*out->transport) {
		rz_frida_uri_fini(out);
		return false;
	}

	return true;
}

