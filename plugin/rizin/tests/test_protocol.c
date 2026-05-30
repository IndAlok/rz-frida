// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>
#include "minunit.h"

static bool test_method_conversion(void) {
	mu_assert_eq(rz_frida_method_from_string("status"), RZ_FRIDA_METHOD_STATUS, "status method from string");
	mu_assert_eq(rz_frida_method_from_string("devices"), RZ_FRIDA_METHOD_DEVICES, "devices method from string");
	mu_assert_eq(rz_frida_method_from_string("bad"), RZ_FRIDA_METHOD_UNKNOWN, "unknown text maps to the unknown method");
	mu_assert_streq(rz_frida_method_string(RZ_FRIDA_METHOD_LAUNCH), "launch", "launch method to string");
	mu_assert_streq(rz_frida_error_string(RZ_FRIDA_ERROR_INVALID_URI), "invalid_uri", "invalid uri error to string");
	mu_assert_streq(rz_frida_error_string(RZ_FRIDA_ERROR_FRIDA_UNAVAILABLE), "frida_unavailable", "frida unavailable error to string");
	mu_end;
}

static bool test_method_parse(void) {
	RzFridaMethod method = RZ_FRIDA_METHOD_UNKNOWN;
	mu_assert_true(rz_frida_method_parse("attach", &method, NULL), "parse a known method");
	mu_assert_eq(method, RZ_FRIDA_METHOD_ATTACH, "parsed method is attach");
	mu_end;
}

static bool test_success_json(void) {
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	rz_frida_json_ok_empty(pj);
	mu_assert_streq(pj_string(pj), "{\"ok\":true,\"result\":{}}", "ok envelope carries an empty result");
	pj_free(pj);
	mu_end;
}

static bool test_error_json(void) {
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	rz_frida_json_error(pj, RZ_FRIDA_ERROR_INVALID_TARGET, "bad target");
	mu_assert_streq(pj_string(pj), "{\"ok\":false,\"error\":{\"code\":\"invalid_target\",\"message\":\"bad target\"}}", "error envelope carries the code and message");
	pj_free(pj);
	mu_end;
}

static bool test_invalid_method_json(void) {
	RzFridaMethod method = RZ_FRIDA_METHOD_STATUS;
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_method_parse("bad", &method, pj), "unknown method is rejected");
	mu_assert_eq(method, RZ_FRIDA_METHOD_UNKNOWN, "method is reset to unknown on failure");
	mu_assert_streq(pj_string(pj), "{\"ok\":false,\"error\":{\"code\":\"not_implemented\",\"message\":\"unknown method\"}}", "rejection writes an error envelope");
	pj_free(pj);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_method_conversion);
	mu_run_test(test_method_parse);
	mu_run_test(test_success_json);
	mu_run_test(test_error_json);
	mu_run_test(test_invalid_method_json);
	return tests_passed != tests_run;
}

mu_main(all_tests)
