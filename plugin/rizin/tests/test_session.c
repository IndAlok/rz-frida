// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>

#include <assert.h>

static void test_initial_state(void) {
	RzFridaSession *session = rz_frida_session_new();
	assert(session);
	assert(rz_frida_session_state(session) == RZ_FRIDA_SESSION_STATE_NEW);
	assert(RZ_STR_EQ(rz_frida_session_state_string(rz_frida_session_state(session)), "new"));
	assert(rz_frida_session_timeout(session) == RZ_FRIDA_DEFAULT_TIMEOUT_MS);
	assert(!rz_frida_session_is_cancelled(session));
	assert(!rz_frida_session_error(session));
	rz_frida_session_free(session);
}

static void test_timeout_update(void) {
	RzFridaSession *session = rz_frida_session_new();
	assert(session);
	rz_frida_session_set_timeout(session, 7000);
	assert(rz_frida_session_timeout(session) == 7000);
	rz_frida_session_free(session);
}

static void test_cancellation_flag(void) {
	RzFridaSession *session = rz_frida_session_new();
	assert(session);
	rz_frida_session_request_cancel(session);
	assert(rz_frida_session_is_cancelled(session));
	rz_frida_session_free(session);
}

static void test_uri_assignment(void) {
	RzFridaSession *session = rz_frida_session_new();
	assert(session);

	RzFridaUri uri = { 0 };
	assert(rz_frida_uri_parse("frida://attach/local//1234", &uri));
	assert(rz_frida_session_set_uri(session, &uri));
	rz_frida_uri_fini(&uri);

	const RzFridaUri *stored = rz_frida_session_uri(session);
	assert(stored);
	assert(rz_frida_session_state(session) == RZ_FRIDA_SESSION_STATE_RESOLVED);
	assert(RZ_STR_EQ(stored->action, "attach"));
	assert(RZ_STR_EQ(stored->transport, "local"));
	assert(RZ_STR_EQ(stored->device, ""));
	assert(RZ_STR_EQ(stored->target, "1234"));

	rz_frida_session_free(session);
}

static void test_error_state(void) {
	RzFridaSession *session = rz_frida_session_new();
	assert(session);
	rz_frida_session_set_error(session, "failed");
	assert(rz_frida_session_state(session) == RZ_FRIDA_SESSION_STATE_ERROR);
	assert(RZ_STR_EQ(rz_frida_session_error(session), "failed"));
	rz_frida_session_free(session);
}

static void test_free_null(void) {
	rz_frida_session_free(NULL);
}

int main(void) {
	test_initial_state();
	test_timeout_update();
	test_cancellation_flag();
	test_uri_assignment();
	test_error_state();
	test_free_null();
	return 0;
}
