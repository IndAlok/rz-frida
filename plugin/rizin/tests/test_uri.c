// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>
#include "minunit.h"

static bool test_local_attach_uri(void) {
	RzFridaUri uri = { 0 };
	mu_assert_true(rz_frida_uri_parse("frida://attach/local//1234", &uri), "parse local attach URI");
	mu_assert_eq(uri.action_type, RZ_FRIDA_ACTION_ATTACH, "action type is attach");
	mu_assert_eq(uri.transport_type, RZ_FRIDA_TRANSPORT_LOCAL, "transport type is local");
	mu_assert_streq(uri.action, "attach", "action text is attach");
	mu_assert_streq(uri.transport, "local", "transport text is local");
	mu_assert_streq(uri.device, "", "device is empty for local");
	mu_assert_streq(uri.target, "1234", "target is the pid");
	rz_frida_uri_fini(&uri);
	mu_end;
}

static bool test_usb_spawn_uri(void) {
	RzFridaUri uri = { 0 };
	mu_assert_true(rz_frida_uri_parse("frida://spawn/usb/device-1/com.example.app", &uri), "parse usb spawn URI");
	mu_assert_eq(uri.action_type, RZ_FRIDA_ACTION_SPAWN, "action type is spawn");
	mu_assert_eq(uri.transport_type, RZ_FRIDA_TRANSPORT_USB, "transport type is usb");
	mu_assert_streq(uri.action, "spawn", "action text is spawn");
	mu_assert_streq(uri.transport, "usb", "transport text is usb");
	mu_assert_streq(uri.device, "device-1", "device id is preserved");
	mu_assert_streq(uri.target, "com.example.app", "target package is preserved");
	rz_frida_uri_fini(&uri);
	mu_end;
}

static bool test_local_list_uri(void) {
	RzFridaUri uri = { 0 };
	mu_assert_true(rz_frida_uri_parse("frida://list/local//", &uri), "parse local list URI");
	mu_assert_eq(uri.action_type, RZ_FRIDA_ACTION_LIST, "action type is list");
	mu_assert_streq(uri.target, "", "target is empty for list");
	rz_frida_uri_fini(&uri);
	mu_end;
}

static bool test_launch_path_with_slashes(void) {
	RzFridaUri uri = { 0 };
	mu_assert_true(rz_frida_uri_parse("frida://launch/local///bin/ls", &uri), "parse launch URI with a path target");
	mu_assert_streq(uri.target, "/bin/ls", "target keeps its leading slash");
	rz_frida_uri_fini(&uri);
	mu_end;
}

static bool test_usb_list_uri(void) {
	RzFridaUri uri = { 0 };
	mu_assert_true(rz_frida_uri_parse("frida://list/usb//", &uri), "usb list without a device id is allowed");
	mu_assert_eq(uri.action_type, RZ_FRIDA_ACTION_LIST, "action type is list");
	mu_assert_eq(uri.transport_type, RZ_FRIDA_TRANSPORT_USB, "transport type is usb");
	mu_assert_streq(uri.device, "", "device is empty for a usb list");
	rz_frida_uri_fini(&uri);
	mu_end;
}

static bool test_usb_apps_uri(void) {
	RzFridaUri uri = { 0 };
	mu_assert_true(rz_frida_uri_parse("frida://apps/usb/device-1/", &uri), "usb apps with a device id is allowed");
	mu_assert_eq(uri.action_type, RZ_FRIDA_ACTION_APPS, "action type is apps");
	mu_assert_eq(uri.transport_type, RZ_FRIDA_TRANSPORT_USB, "transport type is usb");
	mu_assert_streq(uri.device, "device-1", "device id is preserved");
	rz_frida_uri_fini(&uri);
	mu_end;
}

static bool test_usb_omit_device(void) {
	RzFridaUri uri = { 0 };
	mu_assert_true(rz_frida_uri_parse("frida://attach/usb//1234", &uri), "usb attach may omit the device id");
	mu_assert_eq(uri.transport_type, RZ_FRIDA_TRANSPORT_USB, "transport type is usb");
	mu_assert_streq(uri.device, "", "device is empty for a single-device usb attach");
	mu_assert_streq(uri.target, "1234", "target is preserved");
	rz_frida_uri_fini(&uri);

	mu_assert_true(rz_frida_uri_parse("frida://apps/usb//", &uri), "usb apps may omit the device id");
	mu_assert_eq(uri.action_type, RZ_FRIDA_ACTION_APPS, "action type is apps");
	mu_assert_streq(uri.device, "", "device is empty for a single-device usb apps");
	rz_frida_uri_fini(&uri);
	mu_end;
}

static bool test_remote_attach_uri(void) {
	RzFridaUri uri = { 0 };
	mu_assert_true(rz_frida_uri_parse("frida://attach/remote/127.0.0.1:27042/4321", &uri), "parse remote attach URI");
	mu_assert_eq(uri.transport_type, RZ_FRIDA_TRANSPORT_REMOTE, "transport type is remote");
	mu_assert_streq(uri.device, "127.0.0.1:27042", "device is the host:port pair");
	rz_frida_uri_fini(&uri);
	mu_end;
}

static bool test_action_transport_conversion(void) {
	mu_assert_streq(rz_frida_action_string(RZ_FRIDA_ACTION_APPS), "apps", "apps action to string");
	mu_assert_eq(rz_frida_action_from_string("launch"), RZ_FRIDA_ACTION_LAUNCH, "launch action from string");
	mu_assert_streq(rz_frida_transport_string(RZ_FRIDA_TRANSPORT_USB), "usb", "usb transport to string");
	mu_assert_eq(rz_frida_transport_from_string("remote"), RZ_FRIDA_TRANSPORT_REMOTE, "remote transport from string");
	mu_end;
}

static bool test_target_pid_parsing(void) {
	ut32 pid = 1;
	mu_assert_true(rz_frida_uri_target_pid("1234", &pid), "decimal target parses as a pid");
	mu_assert_eq(pid, 1234, "parsed pid keeps its value");
	mu_assert_true(rz_frida_uri_target_pid("0", &pid), "zero parses as a pid");
	mu_assert_eq(pid, 0, "zero pid keeps its value");
	mu_assert_true(rz_frida_uri_target_pid("4294967295", &pid), "ut32 max parses as a pid");
	mu_assert_eq(pid, UT32_MAX, "ut32 max keeps its value");

	mu_assert_false(rz_frida_uri_target_pid("", &pid), "empty target is not a pid");
	mu_assert_false(rz_frida_uri_target_pid("com.example.app", &pid), "package name is not a pid");
	mu_assert_false(rz_frida_uri_target_pid("/bin/ls", &pid), "path is not a pid");
	mu_assert_false(rz_frida_uri_target_pid("12ab", &pid), "trailing letters reject the pid");
	mu_assert_false(rz_frida_uri_target_pid("0x10", &pid), "hex notation is not a decimal pid");
	mu_assert_false(rz_frida_uri_target_pid("-1", &pid), "negative numbers are not a pid");
	mu_assert_false(rz_frida_uri_target_pid("4294967296", &pid), "value above ut32 max is rejected");
	mu_assert_false(rz_frida_uri_target_pid("99999999999999999999", &pid), "overflowing value is rejected");
	mu_end;
}

static bool test_invalid_uris(void) {
	RzFridaUri uri = { 0 };
	mu_assert_false(rz_frida_uri_parse("gdb://attach/local//1234", &uri), "wrong scheme is rejected");
	mu_assert_false(rz_frida_uri_parse("frida://", &uri), "empty path is rejected");
	mu_assert_false(rz_frida_uri_parse("frida://attach/local//", &uri), "missing target is rejected");
	mu_assert_false(rz_frida_uri_parse("frida://attach/usb//", &uri), "usb attach without a target is rejected");
	mu_assert_false(rz_frida_uri_parse("frida://list/local//1234", &uri), "list with a target is rejected");
	mu_assert_false(rz_frida_uri_parse("frida://apps/usb//com.example.app", &uri), "apps with a target is rejected");
	mu_assert_false(rz_frida_uri_parse("frida://attach/remote/localhost/1234", &uri), "remote without a port is rejected");
	mu_assert_false(rz_frida_uri_parse("frida://attach/other//1234", &uri), "unknown transport is rejected");
	mu_assert_false(rz_frida_uri_parse("frida://other/local//1234", &uri), "unknown action is rejected");
	mu_assert_false(rz_frida_uri_parse("frida://attach/local/device/1234", &uri), "local with a device is rejected");
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_local_attach_uri);
	mu_run_test(test_usb_spawn_uri);
	mu_run_test(test_local_list_uri);
	mu_run_test(test_launch_path_with_slashes);
	mu_run_test(test_usb_list_uri);
	mu_run_test(test_usb_apps_uri);
	mu_run_test(test_usb_omit_device);
	mu_run_test(test_remote_attach_uri);
	mu_run_test(test_action_transport_conversion);
	mu_run_test(test_target_pid_parsing);
	mu_run_test(test_invalid_uris);
	return tests_passed != tests_run;
}

mu_main(all_tests)
