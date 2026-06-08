// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>
#include "minunit.h"

static int dispose_calls = 0;
static void *disposed_state = NULL;

static void test_backend_dispose(RzFridaSession *session) {
	dispose_calls++;
	disposed_state = rz_frida_session_backend_state(session);
}

static int cancel_calls = 0;
static void *cancel_user = NULL;

static void record_cancel(void *user) {
	cancel_calls++;
	cancel_user = user;
}

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

static bool test_cancel_hook_runs(void) {
	cancel_calls = 0;
	cancel_user = NULL;
	int marker = 0;

	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");
	rz_frida_session_set_cancel_hook(session, &marker, record_cancel);
	rz_frida_session_request_cancel(session);
	mu_assert_eq(cancel_calls, 1, "request_cancel invokes the cancel hook once");
	mu_assert_ptreq(cancel_user, &marker, "cancel hook receives its user data");
	mu_assert_true(rz_frida_session_is_cancelled(session), "cancellation flag is set alongside the hook");

	rz_frida_session_set_cancel_hook(session, NULL, NULL);
	rz_frida_session_request_cancel(session);
	mu_assert_eq(cancel_calls, 1, "a cleared hook is not called again");

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

static bool test_state_transitions(void) {
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");

	rz_frida_session_set_state(session, RZ_FRIDA_SESSION_STATE_CONNECTING);
	mu_assert_eq(rz_frida_session_state(session), RZ_FRIDA_SESSION_STATE_CONNECTING, "state moves to connecting");
	mu_assert_eq(rz_frida_session_target_pid(session), 0, "target pid defaults to zero");

	rz_frida_session_set_target_pid(session, 4321);
	mu_assert_eq(rz_frida_session_target_pid(session), 4321, "target pid reflects the update");

	rz_frida_session_set_state(session, RZ_FRIDA_SESSION_STATE_ATTACHED);
	mu_assert_eq(rz_frida_session_state(session), RZ_FRIDA_SESSION_STATE_ATTACHED, "state moves to attached");

	rz_frida_session_set_state(session, RZ_FRIDA_SESSION_STATE_CLOSED);
	mu_assert_eq(rz_frida_session_state(session), RZ_FRIDA_SESSION_STATE_CLOSED, "state moves to closed");

	rz_frida_session_free(session);
	mu_end;
}

static bool test_backend_dispose_runs(void) {
	dispose_calls = 0;
	disposed_state = NULL;
	int marker = 0;

	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");
	mu_assert_null(rz_frida_session_backend_state(session), "backend state starts NULL");

	rz_frida_session_set_backend_state(session, &marker, test_backend_dispose);
	mu_assert_ptreq(rz_frida_session_backend_state(session), &marker, "backend state is stored");

	rz_frida_session_free(session);
	mu_assert_eq(dispose_calls, 1, "dispose callback runs exactly once on free");
	mu_assert_ptreq(disposed_state, &marker, "dispose sees the backend state it owns");
	mu_end;
}

static bool test_backend_dispose_optional(void) {
	int marker = 0;
	RzFridaSession *session = rz_frida_session_new();
	mu_assert_notnull(session, "allocate session");
	rz_frida_session_set_backend_state(session, &marker, NULL);
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
	mu_run_test(test_cancel_hook_runs);
	mu_run_test(test_uri_assignment);
	mu_run_test(test_error_state);
	mu_run_test(test_state_transitions);
	mu_run_test(test_backend_dispose_runs);
	mu_run_test(test_backend_dispose_optional);
	mu_run_test(test_free_null);
	return tests_passed != tests_run;
}

mu_main(all_tests)
