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

static bool test_eval_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_eval(session, "Process.arch", pj), "eval fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

static bool test_mem_read_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_mem_read(session, 0x1000, 16, pj), "memory read fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

static bool test_mem_write_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	const ut8 bytes[] = { 0xde, 0xad, 0xbe, 0xef };
	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_mem_write(session, 0x1000, bytes, sizeof(bytes), pj), "memory write fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

static bool test_ranges_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_ranges(session, false, pj), "range listing fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

static bool test_threads_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_threads(session, pj), "thread listing fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

static bool test_modules_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_modules(session, false, pj), "module listing fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

static bool test_exports_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_exports(session, "libc.so", pj), "export listing fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

static bool test_imports_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_imports(session, "libc.so", pj), "import listing fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

static bool test_symbols_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_symbols(session, "libc.so", pj), "symbol listing fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

static bool test_ping_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_ping(session, pj), "ping fails without frida-core");
	mu_assert_streq(pj_string(pj),
		"{\"ok\":false,\"error\":{\"code\":\"frida_unavailable\",\"message\":\"frida-core support is not enabled\"}}",
		"frida-less backend reports the feature as unavailable");
	pj_free(pj);
	rz_frida_session_free(session);
	mu_end;
}

static bool test_messages_unavailable(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	PJ *pj = pj_new();
	mu_assert_notnull(pj, "allocate json builder");
	mu_assert_false(rz_frida_backend_messages(session, pj), "messages fails without frida-core");
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
	mu_run_test(test_eval_unavailable);
	mu_run_test(test_mem_read_unavailable);
	mu_run_test(test_mem_write_unavailable);
	mu_run_test(test_ranges_unavailable);
	mu_run_test(test_threads_unavailable);
	mu_run_test(test_modules_unavailable);
	mu_run_test(test_exports_unavailable);
	mu_run_test(test_imports_unavailable);
	mu_run_test(test_symbols_unavailable);
	mu_run_test(test_ping_unavailable);
	mu_run_test(test_messages_unavailable);
	return tests_passed != tests_run;
}

mu_main(all_tests)
