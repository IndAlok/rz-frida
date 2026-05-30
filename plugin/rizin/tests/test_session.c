// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>
#include "minunit.h"

static bool test_session_new_state(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");
	mu_assert_eq(rz_frida_session_state(session), RZ_FRIDA_SESSION_STATE_NEW, "fresh session is in the new state");
	mu_assert_streq(rz_frida_session_state_string(rz_frida_session_state(session)), "new", "new state stringifies");
	mu_assert_eq(rz_frida_session_timeout(session), RZ_FRIDA_DEFAULT_TIMEOUT_MS, "default timeout is applied");
	mu_assert_false(rz_frida_session_is_cancelled(session), "fresh session is not cancelled");
	mu_assert_null(rz_frida_session_error(session), "fresh session has no error");
	rz_frida_session_free(session);
	mu_end;
}

static bool test_timeout_update(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");
	rz_frida_session_set_timeout(session, 7000);
	mu_assert_eq(rz_frida_session_timeout(session), 7000, "timeout reflects the update");
	rz_frida_session_free(session);
	mu_end;
}

static bool test_cancellation_flag(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");
	rz_frida_session_request_cancel(session);
	mu_assert_true(rz_frida_session_is_cancelled(session), "cancellation flag is set after a request");
	rz_frida_session_free(session);
	mu_end;
}

static bool test_uri_assignment(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	RzFridaUri uri = { 0 };
	mu_assert_true(rz_frida_uri_parse("frida://attach/local//1234", &uri), "parse attach URI");
	mu_assert_true(rz_frida_session_set_uri(session, &uri), "assign the URI to the session");
	rz_frida_uri_fini(&uri);

	const RzFridaUri *stored = rz_frida_session_uri(session);
	mu_assert_notnull(stored, "session retains the URI");
	mu_assert_eq(rz_frida_session_state(session), RZ_FRIDA_SESSION_STATE_RESOLVED, "session moves to resolved after assignment");
	mu_assert_streq(stored->action, "attach", "stored action is attach");
	mu_assert_streq(stored->transport, "local", "stored transport is local");
	mu_assert_streq(stored->device, "", "stored device is empty for local");
	mu_assert_streq(stored->target, "1234", "stored target is the pid");

	rz_frida_session_free(session);
	mu_end;
}

static bool test_error_state(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");
	rz_frida_session_set_error(session, "failed");
	mu_assert_eq(rz_frida_session_state(session), RZ_FRIDA_SESSION_STATE_ERROR, "session moves to the error state");
	mu_assert_streq(rz_frida_session_error(session), "failed", "session retains the error text");
	rz_frida_session_free(session);
	mu_end;
}

static bool test_free_null(void) {
	rz_frida_session_free(NULL);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_session_new_state);
	mu_run_test(test_timeout_update);
	mu_run_test(test_cancellation_flag);
	mu_run_test(test_uri_assignment);
	mu_run_test(test_error_state);
	mu_run_test(test_free_null);
	return tests_passed != tests_run;
}

mu_main(all_tests)
