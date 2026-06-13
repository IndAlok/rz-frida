// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_frida.h>
#include "minunit.h"

extern RzCorePlugin rz_core_plugin_frida;

static bool test_plugin_registration(RzCore *core) {
	mu_assert_true(rz_core_plugin_add(core, &rz_core_plugin_frida), "register the frida plugin");
	mu_assert_notnull(rz_core_plugin_context_get(core, &rz_core_plugin_frida), "plugin context is created on registration");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "frida"), "frida group command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridas"), "fridas command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridau"), "fridau command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridad"), "fridad command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridap"), "fridap command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridaa"), "fridaa command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridao"), "fridao command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridar"), "fridar command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridac"), "fridac command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridae"), "fridae command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridal"), "fridal command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridai"), "fridai command is registered");
	mu_assert_notnull(rz_cmd_get_desc(core->rcmd, "fridam"), "fridam command is registered");
	mu_end;
}

static bool test_status_command(RzCore *core) {
	char *status = rz_core_cmd_str(core, "fridasj");
	mu_assert_notnull(status, "status command returns output");
	mu_assert_streq(status, "{\"ok\":true,\"result\":{\"active\":false,\"state\":\"closed\"}}\n", "status reports an inactive session");
	RZ_FREE(status);
	mu_end;
}

static bool test_uri_command(RzCore *core) {
	char *uri = rz_core_cmd_str(core, "fridauj frida://attach/local//1234");
	mu_assert_notnull(uri, "uri command returns output");
	mu_assert_streq(uri,
		"{\"ok\":true,\"result\":{\"action\":\"attach\",\"transport\":\"local\",\"device\":\"\",\"target\":\"1234\"}}\n",
		"uri command echoes the parsed components");
	RZ_FREE(uri);
	mu_end;
}

static bool test_invalid_uri_command(RzCore *core) {
	char *uri = rz_core_cmd_str(core, "fridauj gdb://attach/local//1234");
	mu_assert_notnull(uri, "uri command returns output");
	mu_assert_streq(uri,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_uri\",\"message\":\"invalid Frida URI\"}}\n",
		"uri command rejects a non-frida scheme");
	RZ_FREE(uri);
	mu_end;
}

static bool test_devices_command(RzCore *core) {
	char *devices = rz_core_cmd_str(core, "fridadj");
	mu_assert_notnull(devices, "devices command returns output");
	mu_assert_true(rz_str_startswith(devices, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(devices, "{\"ok\":true,\"result\":{\"devices\":["),
		"devices command emits an ok or error envelope");
	RZ_FREE(devices);
	mu_end;
}

static bool test_processes_command(RzCore *core) {
	char *processes = rz_core_cmd_str(core, "fridapj");
	mu_assert_notnull(processes, "processes command returns output");
	mu_assert_true(rz_str_startswith(processes, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(processes, "{\"ok\":true,\"result\":{\"processes\":["),
		"processes command emits an ok or error envelope");
	RZ_FREE(processes);
	mu_end;
}

static bool test_processes_device_command(RzCore *core) {
	char *processes = rz_core_cmd_str(core, "fridapj frida://list/usb//");
	mu_assert_notnull(processes, "device-scoped processes command returns output");
	mu_assert_true(rz_str_startswith(processes, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(processes, "{\"ok\":true,\"result\":{\"processes\":["),
		"device-scoped processes command emits an ok or error envelope");
	RZ_FREE(processes);
	mu_end;
}

static bool test_apps_command(RzCore *core) {
	char *apps = rz_core_cmd_str(core, "fridaaj");
	mu_assert_notnull(apps, "apps command returns output");
	mu_assert_true(rz_str_startswith(apps, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(apps, "{\"ok\":true,\"result\":{\"apps\":["),
		"apps command emits an ok or error envelope");
	RZ_FREE(apps);
	mu_end;
}

static bool test_invalid_listing_uri(RzCore *core) {
	char *processes = rz_core_cmd_str(core, "fridapj gdb://list/local//");
	mu_assert_notnull(processes, "listing command returns output");
	mu_assert_streq(processes,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_uri\",\"message\":\"invalid Frida URI\"}}\n",
		"a non-frida selector is rejected before touching the backend");
	RZ_FREE(processes);
	mu_end;
}

static bool test_mismatched_listing_uri(RzCore *core) {
	char *processes = rz_core_cmd_str(core, "fridapj frida://apps/usb//");
	mu_assert_notnull(processes, "listing command returns output");
	mu_assert_streq(processes,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_uri\",\"message\":\"URI action does not match the command\"}}\n",
		"a listing command rejects a URI with the wrong action");
	RZ_FREE(processes);
	mu_end;
}

static bool test_resume_without_session(RzCore *core) {
	char *resume = rz_core_cmd_str(core, "fridarj");
	mu_assert_notnull(resume, "resume command returns output");
	mu_assert_streq(resume,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"resume without an open session reports the precondition failure");
	RZ_FREE(resume);
	mu_end;
}

static bool test_close_without_session(RzCore *core) {
	char *close = rz_core_cmd_str(core, "fridacj");
	mu_assert_notnull(close, "close command returns output");
	mu_assert_streq(close,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"close without an open session reports the precondition failure");
	RZ_FREE(close);
	mu_end;
}

static bool test_eval_without_session(RzCore *core) {
	char *eval = rz_core_cmd_str(core, "fridaej Process.arch");
	mu_assert_notnull(eval, "eval command returns output");
	mu_assert_streq(eval,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"eval without an open session reports the precondition failure");
	RZ_FREE(eval);
	mu_end;
}

static bool test_load_without_session(RzCore *core) {
	char *load = rz_core_cmd_str(core, "fridalj hook.js");
	mu_assert_notnull(load, "load command returns output");
	mu_assert_streq(load,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"load without an open session reports the precondition failure");
	RZ_FREE(load);
	mu_end;
}

static bool test_ping_without_session(RzCore *core) {
	char *ping = rz_core_cmd_str(core, "fridaij");
	mu_assert_notnull(ping, "ping command returns output");
	mu_assert_streq(ping,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"ping without an open session reports the precondition failure");
	RZ_FREE(ping);
	mu_end;
}

static bool test_messages_without_session(RzCore *core) {
	char *messages = rz_core_cmd_str(core, "fridamj");
	mu_assert_notnull(messages, "messages command returns output");
	mu_assert_streq(messages,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"no session is open\"}}\n",
		"messages without an open session reports the precondition failure");
	RZ_FREE(messages);
	mu_end;
}

static bool test_invalid_open_uri(RzCore *core) {
	char *open = rz_core_cmd_str(core, "fridaoj gdb://attach/local//1234");
	mu_assert_notnull(open, "open command returns output");
	mu_assert_streq(open,
		"{\"ok\":false,\"error\":{\"code\":\"invalid_uri\",\"message\":\"invalid Frida URI\"}}\n",
		"open rejects a non-frida scheme before touching the backend");
	RZ_FREE(open);
	mu_end;
}

static bool test_open_command(RzCore *core) {
	char *open = rz_core_cmd_str(core, "fridaoj frida://attach/local//1234");
	mu_assert_notnull(open, "open command returns output");
	mu_assert_true(rz_str_startswith(open, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(open, "{\"ok\":true,\"result\":{\"action\":"),
		"open command emits an ok or error envelope");
	RZ_FREE(open);
	mu_end;
}

static bool test_open_usb_command(RzCore *core) {
	char *open = rz_core_cmd_str(core, "fridaoj frida://attach/usb//com.example.app");
	mu_assert_notnull(open, "usb open command returns output");
	mu_assert_true(rz_str_startswith(open, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(open, "{\"ok\":true,\"result\":{\"action\":"),
		"usb open routes a process-name target to the backend");
	RZ_FREE(open);
	mu_end;
}

static bool test_open_remote_command(RzCore *core) {
	char *open = rz_core_cmd_str(core, "fridaoj frida://attach/remote/127.0.0.1:27042/1234");
	mu_assert_notnull(open, "remote open command returns output");
	mu_assert_true(rz_str_startswith(open, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(open, "{\"ok\":true,\"result\":{\"action\":"),
		"remote open routes to the backend");
	RZ_FREE(open);
	mu_end;
}

static bool test_close_command(RzCore *core) {
	char *close = rz_core_cmd_str(core, "fridacj");
	mu_assert_notnull(close, "close command returns output");
	mu_assert_true(rz_str_startswith(close, "{\"ok\":false,\"error\":{\"code\":\"") ||
			rz_str_startswith(close, "{\"ok\":true,\"result\":{\"pid\":"),
		"close emits an ok or error envelope depending on whether open established a session");
	RZ_FREE(close);
	mu_end;
}

static bool test_plugin_unregistration(RzCore *core) {
	mu_assert_true(rz_core_plugin_del(core, &rz_core_plugin_frida), "unregister the frida plugin");
	mu_assert_null(rz_core_plugin_context_get(core, &rz_core_plugin_frida), "plugin context is released on unregistration");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "frida"), "frida group command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridas"), "fridas command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridau"), "fridau command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridad"), "fridad command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridap"), "fridap command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridaa"), "fridaa command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridao"), "fridao command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridar"), "fridar command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridac"), "fridac command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridae"), "fridae command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridal"), "fridal command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridai"), "fridai command is removed");
	mu_assert_null(rz_cmd_get_desc(core->rcmd, "fridam"), "fridam command is removed");
	mu_end;
}

int all_tests(void) {
	RzCore *core = rz_core_new();
	if (!core) {
		printf("Cannot create RzCore\n");
		return 1;
	}

	mu_run_test(test_plugin_registration, core);
	mu_run_test(test_status_command, core);
	mu_run_test(test_uri_command, core);
	mu_run_test(test_invalid_uri_command, core);
	mu_run_test(test_devices_command, core);
	mu_run_test(test_processes_command, core);
	mu_run_test(test_processes_device_command, core);
	mu_run_test(test_apps_command, core);
	mu_run_test(test_invalid_listing_uri, core);
	mu_run_test(test_mismatched_listing_uri, core);
	mu_run_test(test_resume_without_session, core);
	mu_run_test(test_close_without_session, core);
	mu_run_test(test_eval_without_session, core);
	mu_run_test(test_load_without_session, core);
	mu_run_test(test_ping_without_session, core);
	mu_run_test(test_messages_without_session, core);
	mu_run_test(test_invalid_open_uri, core);
	mu_run_test(test_open_command, core);
	mu_run_test(test_open_usb_command, core);
	mu_run_test(test_open_remote_command, core);
	mu_run_test(test_close_command, core);
	mu_run_test(test_plugin_unregistration, core);

	rz_core_free(core);
	return tests_passed != tests_run;
}

mu_main(all_tests)
