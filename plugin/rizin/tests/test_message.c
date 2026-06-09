// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_frida.h>
#include "minunit.h"

static bool test_parse_send_message(void) {
	RzFridaAgentMessage msg = { 0 };
	mu_assert_true(rz_frida_agent_message_parse(
			       "{\"type\":\"send\",\"payload\":{\"type\":\"agent.ready\",\"version\":1}}", &msg),
		"send message parses");
	mu_assert_eq(msg.kind, RZ_FRIDA_AGENT_MESSAGE_SEND, "kind is send");
	mu_assert_streq(msg.payload, "{\"type\":\"agent.ready\",\"version\":1}", "payload round-trips as JSON text");
	mu_assert_null(msg.description, "send carries no description");
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_parse_error_message(void) {
	RzFridaAgentMessage msg = { 0 };
	mu_assert_true(rz_frida_agent_message_parse(
			       "{\"type\":\"error\",\"description\":\"boom\",\"stack\":\"at agent.js\"}", &msg),
		"error message parses");
	mu_assert_eq(msg.kind, RZ_FRIDA_AGENT_MESSAGE_ERROR, "kind is error");
	mu_assert_streq(msg.description, "boom", "description is captured");
	mu_assert_streq(msg.stack, "at agent.js", "stack is captured");
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_parse_log_message(void) {
	RzFridaAgentMessage msg = { 0 };
	mu_assert_true(rz_frida_agent_message_parse(
			       "{\"type\":\"log\",\"level\":\"warning\",\"payload\":\"heads up\"}", &msg),
		"log message parses");
	mu_assert_eq(msg.kind, RZ_FRIDA_AGENT_MESSAGE_LOG, "kind is log");
	mu_assert_streq(msg.level, "warning", "level is captured");
	mu_assert_streq(msg.text, "heads up", "log text is captured");
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_parse_unknown_type(void) {
	RzFridaAgentMessage msg = { 0 };
	mu_assert_false(rz_frida_agent_message_parse("{\"type\":\"frobnicate\"}", &msg), "unknown type is rejected");
	mu_assert_eq(msg.kind, RZ_FRIDA_AGENT_MESSAGE_UNKNOWN, "kind stays unknown on rejection");
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_parse_malformed_message(void) {
	RzFridaAgentMessage msg = { 0 };
	mu_assert_false(rz_frida_agent_message_parse("{ this is not json", &msg), "broken json is rejected");
	mu_assert_false(rz_frida_agent_message_parse("[1,2,3]", &msg), "a non-object is rejected");
	mu_assert_false(rz_frida_agent_message_parse("{\"type\":42}", &msg), "a non-string type is rejected");
	mu_assert_false(rz_frida_agent_message_parse("{\"payload\":1}", &msg), "a missing type is rejected");
	rz_frida_agent_message_fini(&msg);
	mu_end;
}

static bool test_response_ok(void) {
	RzFridaResponse resp = { 0 };
	mu_assert_true(rz_frida_response_parse("{\"id\":7,\"ok\":true,\"result\":{\"version\":1}}", &resp),
		"ok response parses");
	mu_assert_eq(resp.id, 7, "response id is read");
	mu_assert_true(resp.ok, "response is marked ok");
	mu_assert_streq(resp.result, "{\"version\":1}", "result round-trips as JSON text");
	mu_assert_null(resp.error, "ok response carries no error");
	rz_frida_response_fini(&resp);
	mu_end;
}

static bool test_response_error_string(void) {
	RzFridaResponse resp = { 0 };
	mu_assert_true(rz_frida_response_parse("{\"id\":8,\"ok\":false,\"error\":\"bad request\"}", &resp),
		"error response parses");
	mu_assert_eq(resp.id, 8, "response id is read");
	mu_assert_false(resp.ok, "response is marked not ok");
	mu_assert_streq(resp.error, "bad request", "string error is captured");
	mu_assert_null(resp.result, "error response carries no result");
	rz_frida_response_fini(&resp);
	mu_end;
}

static bool test_response_error_object(void) {
	RzFridaResponse resp = { 0 };
	mu_assert_true(rz_frida_response_parse(
			       "{\"id\":9,\"ok\":false,\"error\":{\"code\":\"internal_error\",\"message\":\"boom\"}}", &resp),
		"object error response parses");
	mu_assert_streq(resp.error, "{\"code\":\"internal_error\",\"message\":\"boom\"}", "object error round-trips as JSON text");
	rz_frida_response_fini(&resp);
	mu_end;
}

static bool test_response_rejects_non_reply(void) {
	RzFridaResponse resp = { 0 };
	mu_assert_false(rz_frida_response_parse("{\"ok\":true,\"result\":1}", &resp), "a payload without id is not a reply");
	mu_assert_false(rz_frida_response_parse("{\"id\":\"oops\"}", &resp), "a non-integer id is rejected");
	mu_assert_false(rz_frida_response_parse("{ broken", &resp), "broken json is rejected");
	rz_frida_response_fini(&resp);
	mu_end;
}

static bool test_pending_lifecycle(void) {
	RzFridaPending *pending = rz_frida_pending_new();
	mu_assert_notnull(pending, "allocate pending registry");

	mu_assert_eq(rz_frida_pending_next_id(pending), 1, "ids start at one");
	mu_assert_eq(rz_frida_pending_next_id(pending), 2, "ids increase by one");
	mu_assert_eq(rz_frida_pending_next_id(pending), 3, "ids keep increasing");

	mu_assert_true(rz_frida_pending_add(pending, 1), "add a request id");
	mu_assert_true(rz_frida_pending_add(pending, 2), "add another request id");
	mu_assert_false(rz_frida_pending_add(pending, 1), "adding a duplicate id fails");
	mu_assert_eq(rz_frida_pending_count(pending), 2, "two ids are tracked");

	mu_assert_true(rz_frida_pending_contains(pending, 1), "tracked id is present");
	mu_assert_false(rz_frida_pending_contains(pending, 9), "untracked id is absent");

	mu_assert_true(rz_frida_pending_take(pending, 1), "take a tracked id");
	mu_assert_false(rz_frida_pending_take(pending, 1), "taking it again fails");
	mu_assert_eq(rz_frida_pending_count(pending), 1, "one id remains");

	rz_frida_pending_clear(pending);
	mu_assert_eq(rz_frida_pending_count(pending), 0, "clear empties the registry");

	rz_frida_pending_free(pending);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_parse_send_message);
	mu_run_test(test_parse_error_message);
	mu_run_test(test_parse_log_message);
	mu_run_test(test_parse_unknown_type);
	mu_run_test(test_parse_malformed_message);
	mu_run_test(test_response_ok);
	mu_run_test(test_response_error_string);
	mu_run_test(test_response_error_object);
	mu_run_test(test_response_rejects_non_reply);
	mu_run_test(test_pending_lifecycle);
	return tests_passed != tests_run;
}

mu_main(all_tests)
