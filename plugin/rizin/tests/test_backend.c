// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

#include <assert.h>

int main(void) {
	PJ *pj = pj_new();
	assert(pj);
	assert(!rz_frida_devices_json(pj));
	assert(RZ_STR_EQ(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}"));
	pj_free(pj);

	return 0;
}
