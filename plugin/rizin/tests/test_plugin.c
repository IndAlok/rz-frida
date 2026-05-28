// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_frida.h>

#include <assert.h>

extern RzCorePlugin rz_core_plugin_frida;

int main(void) {
	RzCore *core = rz_core_new();
	assert(core);

	assert(rz_core_plugin_add(core, &rz_core_plugin_frida));
	assert(rz_core_plugin_context_get(core, &rz_core_plugin_frida));
	assert(rz_cmd_get_desc(core->rcmd, "frida"));

	char *status = rz_core_cmd_str(core, "frida statusj");
	assert(status);
	assert(RZ_STR_EQ(status, "{\"ok\":true,\"result\":{\"active\":false,\"state\":\"closed\"}}\n"));
	RZ_FREE(status);

	char *uri = rz_core_cmd_str(core, "frida urij frida://attach/local//1234");
	assert(uri);
	assert(RZ_STR_EQ(uri,
		"{\"ok\":true,\"result\":{\"action\":\"attach\",\"transport\":\"local\",\"device\":\"\",\"target\":\"1234\"}}\n"));
	RZ_FREE(uri);

	char *devices = rz_core_cmd_str(core, "frida devicesj");
	if (devices) {
		assert(rz_str_startswith(devices, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(devices, "{\"ok\":true,\"result\":{\"devices\":["));
		RZ_FREE(devices);
	}

	assert(rz_core_plugin_del(core, &rz_core_plugin_frida));
	assert(!rz_core_plugin_context_get(core, &rz_core_plugin_frida));
	assert(!rz_cmd_get_desc(core->rcmd, "frida"));

	rz_core_free(core);
	return 0;
}
