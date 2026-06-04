// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>
#include "minunit.h"

static bool test_devices_unavailable(void) {
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_devices_json(pj), "device enumeration fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	mu_end;
}

static bool test_processes_unavailable(void) {
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_processes_json(NULL, pj), "process enumeration fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	mu_end;
}

static bool test_apps_unavailable(void) {
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_apps_json(NULL, pj), "application enumeration fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	mu_end;
}

static bool test_open_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	RzFridaUri uri = { 0 };
	mu_assert_true(rz_frida_uri_parse("frida://attach/local//1234", &uri), "parse attach URI");
	mu_assert_true(rz_frida_session_set_uri(session, &uri), "assign the URI to the session");
	rz_frida_uri_fini(&uri);

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_open(session, pj), "open fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	mu_assert_null(rz_frida_session_backend_state(session), "no backend state is attached when open fails");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

static bool test_resume_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_resume(session, pj), "resume fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

static bool test_close_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_close(session, pj), "close fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_devices_unavailable);
	mu_run_test(test_processes_unavailable);
	mu_run_test(test_apps_unavailable);
	mu_run_test(test_open_unavailable);
	mu_run_test(test_resume_unavailable);
	mu_run_test(test_close_unavailable);
	return tests_passed != tests_run;
}

mu_main(all_tests)
