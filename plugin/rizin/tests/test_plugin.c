// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_frida.h>

#include <assert.h>

extern RzCorePlugin rz_core_plugin_frida;

static void test_plugin_registration(RzCore *core) {
	assert(rz_core_plugin_add(core, &rz_core_plugin_frida));
	assert(rz_core_plugin_context_get(core, &rz_core_plugin_frida));
	assert(rz_cmd_get_desc(core->rcmd, "frida"));
	assert(rz_cmd_get_desc(core->rcmd, "fridas"));
	assert(rz_cmd_get_desc(core->rcmd, "fridau"));
	assert(rz_cmd_get_desc(core->rcmd, "fridad"));
}

static void test_status_command(RzCore *core) {
	char *status = rz_core_cmd_str(core, "fridasj");
	assert(status);
	assert(RZ_STR_EQ(status, "{\"ok\":true,\"result\":{\"active\":false,\"state\":\"closed\"}}\n"));
	RZ_FREE(status);
}

static void test_uri_command(RzCore *core) {
	char *uri = rz_core_cmd_str(core, "fridauj frida://attach/local//1234");
	assert(uri);
	assert(RZ_STR_EQ(uri,
		"{\"ok\":true,\"result\":{\"action\":\"attach\",\"transport\":\"local\",\"device\":\"\",\"target\":\"1234\"}}\n"));
	RZ_FREE(uri);
}

static void test_invalid_uri_command(RzCore *core) {
	char *uri = rz_core_cmd_str(core, "fridauj gdb://attach/local//1234");
	assert(uri);
	assert(RZ_STR_EQ(uri,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_uri\",\"message\":\"invalid Frida URI\"}}\n"));
	RZ_FREE(uri);
}

static void test_devices_command(RzCore *core) {
	char *devices = rz_core_cmd_str(core, "fridadj");
	assert(devices);
	assert(rz_str_startswith(devices, "{\"ok\":false,\"error\":{\"code\":\"") ||
		rz_str_startswith(devices, "{\"ok\":true,\"result\":{\"devices\":["));
	RZ_FREE(devices);
}

static void test_plugin_unregistration(RzCore *core) {
	assert(rz_core_plugin_del(core, &rz_core_plugin_frida));
	assert(!rz_core_plugin_context_get(core, &rz_core_plugin_frida));
	assert(!rz_cmd_get_desc(core->rcmd, "frida"));
	assert(!rz_cmd_get_desc(core->rcmd, "fridas"));
	assert(!rz_cmd_get_desc(core->rcmd, "fridau"));
	assert(!rz_cmd_get_desc(core->rcmd, "fridad"));
}

int main(void) {
	RzCore *core = rz_core_new();
	assert(core);

	test_plugin_registration(core);
	test_status_command(core);
	test_uri_command(core);
	test_invalid_uri_command(core);
	test_devices_command(core);
	test_plugin_unregistration(core);

	rz_core_free(core);
	return 0;
}
